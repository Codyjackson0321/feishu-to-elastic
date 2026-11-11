"""Map Feishu behavior audit log entries to Elastic Common Schema (ECS) documents.

Fields with an ECS equivalent are mapped to it; everything else is kept under
the custom ``feishu.audit.*`` namespace. The raw entry is preserved in
``event.original``.

Enum meanings come from the Feishu audit log appendix:
https://open.feishu.cn/document/server-docs/security_and_compliance-v1/audit_log/appendix
"""

import ipaddress
import json
import re
from datetime import UTC, datetime
from urllib.parse import urlsplit

ECS_VERSION = "8.17.0"
DATASET = "feishu.audit"

EVENT_MODULES = {
    1: "docs",
    2: "im",
    3: "contacts",
    4: "workplace",
    5: "vc",
    6: "account",
    9: "moments",
    13: "okr",
    16: "mail",
    18: "approval",
    21: "calendar",
}

TERMINAL_TYPES = {0: "ios", 1: "android", 2: "pc", 3: "web"}
APP_TERMINALS = {"ios", "android", "pc"}

OPERATOR_TYPES = {1: "member", 12: "bot", 1001: "external_member"}
USER_OPERATOR_TYPES = {1, 1001}

OBJECT_TYPES = {
    "1": "user",
    "2": "department",
    "3": "tenant",
    "4": "chat",
    "5": "doc",
    "6": "sheet",
    "7": "file",
    "8": "folder",
    "9": "mindnote",
    "10": "bitable",
    "11": "slide",
    "12": "bot",
    "13": "call",
    "14": "chat_preview_file",
    "15": "link",
    "16": "im_user",
    "17": "image",
    "18": "video",
    "19": "chat_file",
    "20": "app",
    "21": "local_file",
    "29": "okr",
}
FILE_OBJECT_TYPES = {"5", "6", "7", "8", "9", "10", "11", "14", "17", "18", "19", "21"}

ECS_OS_TYPES = {"linux", "macos", "unix", "windows", "ios", "android"}

_AUTH_START = (["authentication", "session"], ["start"])
_AUTH_END = (["authentication", "session"], ["end"])
_CREDENTIAL_CHANGE = (["iam"], ["user", "change"])
_WEB_ACCESS = (["web"], ["access"])

# event_name -> (event.category, event.type). Unlisted actions get event.type=info.
EVENT_CATEGORIZATION: dict[str, tuple[list[str], list[str]]] = {
    "account_login": _AUTH_START,
    "account_passport_logout": _AUTH_END,
    "account_passport_changeaccount": (["authentication"], ["info"]),
    "email_login": (["authentication"], ["start"]),
    "email_loginthird": (["authentication"], ["start"]),
    "moments_login_official": (["authentication"], ["start"]),
    "account_passport_renew_logoncre": _CREDENTIAL_CHANGE,
    "account_passport_renew_password": _CREDENTIAL_CHANGE,
    "account_passport_update_otp": _CREDENTIAL_CHANGE,
    "account_passport_update_2fa": _CREDENTIAL_CHANGE,
    "account_passport_updatesparecre": _CREDENTIAL_CHANGE,
    "account_passport_renew_fidocre": _CREDENTIAL_CHANGE,
    "account_passport_revoke_appauth": _CREDENTIAL_CHANGE,
    "user_active_exit_team": _CREDENTIAL_CHANGE,
    "workplace_open_app": _WEB_ACCESS,
    "im_open_link": _WEB_ACCESS,
    "email_urlclick": _WEB_ACCESS,
    "space_create_doc": (["file"], ["creation"]),
    "space_read_doc": (["file"], ["access"]),
    "space_edit_doc": (["file"], ["change"]),
    "space_delete_doc": (["file"], ["deletion"]),
    "space_download_file": (["file"], ["access"]),
    "space_export_doc": (["file"], ["access"]),
    "space_update_collaborator_doc": (["file"], ["change"]),
    "space_update_share_setting_doc": (["file"], ["change"]),
}

OP_RESULT_OUTCOMES = {
    "0": "success",
    "success": "success",
    "1": "failure",
    "fail": "failure",
    "failed": "failure",
    "failure": "failure",
}

_MAC_HEX = re.compile(r"[0-9A-Fa-f]{12}")


def to_ecs(entry: dict, namespace: str) -> dict:
    """Convert one raw audit log entry to an ECS document."""
    doc: dict = {}
    event_name = entry.get("event_name") or ""
    event_module = entry.get("event_module")

    _put(doc, "@timestamp", _iso8601(entry["event_time"]))
    _put(doc, "ecs.version", ECS_VERSION)
    _put(doc, "data_stream", {"type": "logs", "dataset": DATASET, "namespace": namespace})

    details, details_display = _drawer_details(entry)
    categories, types = EVENT_CATEGORIZATION.get(event_name, ([], ["info"]))
    outcome = OP_RESULT_OUTCOMES.get(str(details.get("OpResult", "")).lower())
    if outcome is None and event_name in EVENT_CATEGORIZATION:
        outcome = "success"

    _put(doc, "event.kind", "event")
    _put(doc, "event.module", "feishu")
    _put(doc, "event.dataset", DATASET)
    _put(doc, "event.provider", EVENT_MODULES.get(event_module))
    _put(doc, "event.action", event_name)
    _put(doc, "event.category", categories)
    _put(doc, "event.type", types)
    _put(doc, "event.outcome", outcome)
    _put(doc, "event.id", entry.get("unique_id"))
    _put(doc, "event.original", json.dumps(entry, ensure_ascii=False, separators=(",", ":")))

    # Operator -> user / organization
    operator_type = entry.get("operator_type")
    operator_value = entry.get("operator_value")
    operator_detail = entry.get("operator_detail") or {}
    operator_name = operator_detail.get("operator_name") or {}
    display_name = operator_name.get("default_name")
    i18n_names = operator_name.get("i18n_value") or {}
    user_name = i18n_names.get("en_us") or display_name
    if operator_type in USER_OPERATOR_TYPES:
        _put(doc, "user.id", operator_value)
        _put(doc, "user.name", user_name)
        _put(doc, "user.full_name", display_name)
    _put(doc, "organization.id", entry.get("operator_tenant"))
    _put(doc, "organization.name", operator_detail.get("tenant_name"))

    # Client network / device
    audit_context = entry.get("audit_context") or {}
    audit_detail = entry.get("audit_detail") or {}
    terminal_type = audit_context.get("terminal_type")
    terminal = TERMINAL_TYPES.get(terminal_type)
    client_context = next(
        (v for k, v in audit_context.items() if k.endswith("_context") and isinstance(v, dict)),
        {},
    )

    source_ip = entry.get("ip")
    if _is_ip(source_ip):
        _put(doc, "source.ip", source_ip)
        _put(doc, "source.address", source_ip)
    _put(doc, "source.mac", _ecs_mac(audit_detail.get("mc")))

    device_id = client_context.get("did")
    if device_id not in (None, "", "0"):
        _put(doc, "device.id", device_id)
    _put(doc, "device.manufacturer", client_context.get("hw_manuf"))
    _put(doc, "device.model.identifier", audit_detail.get("device_model"))

    _put(doc, "user_agent.original", client_context.get("user_agent"))
    if terminal in APP_TERMINALS:
        _put(doc, "user_agent.name", "Feishu")
    _put(doc, "user_agent.version", client_context.get("app_ver"))
    os_name = audit_detail.get("os")
    _put(doc, "user_agent.os.name", os_name)
    if os_name and os_name.lower() in ECS_OS_TYPES:
        _put(doc, "user_agent.os.type", os_name.lower())
    if terminal == "android":
        _put(doc, "user_agent.os.version", client_context.get("id_r"))

    # Objects -> target user / url / file
    objects, target_users, target_groups, file_names, link = _objects(entry)
    _put(doc, "user.target.id", _one_or_many(target_users))
    _put(doc, "user.target.group.id", _one_or_many(target_groups))
    _put(doc, "file.name", _one_or_many(file_names))
    if link:
        _put(doc, "url", _url_fields(link))

    related_ips = [source_ip] + [
        client_context.get(k)
        for k in ("IP", "active_ip", "route_iip", "route_gip", "wifip", "proxyip")
    ]
    _put(doc, "related.ip", _dedupe(ip for ip in related_ips if _is_ip(ip, allow_unspecified=False)))
    if operator_type in USER_OPERATOR_TYPES:
        _put(doc, "related.user", _dedupe([operator_value, user_name, display_name, *target_users]))

    actor = user_name or operator_value or "unknown operator"
    message = f"{event_name} by {actor}"
    if _is_ip(source_ip):
        message += f" from {source_ip}"
    _put(doc, "message", message)

    # Everything without an ECS home
    feishu = {
        "event_id": entry.get("event_id"),
        "event_module": event_module,
        "terminal_type": terminal_type,
        "terminal": terminal,
        # source.geo is owned by the ingest pipeline's GeoIP lookup; it falls back to this.
        "city": audit_detail.get("city"),
        "operator": _compact(
            {
                "type": operator_type,
                "type_name": OPERATOR_TYPES.get(operator_type),
                "value": operator_value,
                "app_id": entry.get("operator_app"),
                "app_name": entry.get("operator_app_name"),
                "name": _compact(
                    {
                        "default": display_name,
                        "en_us": i18n_names.get("en_us"),
                        "ja_jp": i18n_names.get("ja_jp"),
                        "zh_cn": i18n_names.get("zh_cn"),
                    }
                ),
            }
        ),
        "department_ids": entry.get("department_ids"),
        "objects": objects,
        "details": details,
        "details_display": details_display,
        "extend": entry.get("extend"),
        "client_context": client_context,
        "recipients": entry.get("recipients"),
    }
    _put(doc, "feishu.audit", _compact(feishu))
    return doc


def _drawer_details(entry: dict) -> tuple[dict, dict]:
    """Flatten common_drawers into {info_key: info_val} and {info_key: val_i18n_key}."""
    details: dict[str, str] = {}
    display: dict[str, str] = {}
    drawers = (entry.get("common_drawers") or {}).get("common_draw_info_list") or []
    for item in drawers:
        key = item.get("info_key")
        if not key:
            continue
        details[key] = item.get("info_val", "")
        if item.get("val_i18n_key"):
            display[key] = item["val_i18n_key"]
    return details, display


def _objects(entry: dict) -> tuple[list[dict], list[str], list[str], list[str], str | None]:
    objects: list[dict] = []
    target_users: list[str] = []
    target_groups: list[str] = []
    file_names: list[str] = []
    link: str | None = None
    for obj in entry.get("objects") or []:
        object_type = str(obj.get("object_type", ""))
        value = obj.get("object_value")
        name = obj.get("object_name")
        objects.append(
            _compact(
                {
                    "type": object_type,
                    "type_name": OBJECT_TYPES.get(object_type),
                    "value": value,
                    "name": name,
                    "owner": obj.get("object_owner"),
                    "detail": obj.get("object_detail"),
                }
            )
        )
        if not value:
            continue
        if object_type == "1":
            target_users.append(value)
        elif object_type == "2":
            target_groups.append(value)
        elif object_type == "15" and link is None:
            link = value
        elif object_type in FILE_OBJECT_TYPES and name:
            file_names.append(name)
    return objects, _dedupe(target_users), _dedupe(target_groups), _dedupe(file_names), link


def _url_fields(raw: str) -> dict:
    parts = urlsplit(raw)
    if not parts.scheme or not parts.hostname:
        return {"original": raw}
    try:
        port = parts.port
    except ValueError:
        port = None
    return _compact(
        {
            "original": raw,
            "full": raw,
            "scheme": parts.scheme,
            "domain": parts.hostname,
            "port": port,
            "path": parts.path,
            "query": parts.query,
            "fragment": parts.fragment,
        }
    )


def _iso8601(epoch_seconds: int | str) -> str:
    return datetime.fromtimestamp(int(epoch_seconds), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ecs_mac(raw: str | None) -> str | None:
    """ECS wants MACs as uppercase hex pairs separated by hyphens."""
    if not raw:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", raw)
    if not _MAC_HEX.fullmatch(digits):
        return None
    return "-".join(digits[i : i + 2] for i in range(0, 12, 2)).upper()


def _is_ip(value: object, allow_unspecified: bool = True) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    return allow_unspecified or not addr.is_unspecified


def _put(doc: dict, path: str, value: object) -> None:
    """Set a dotted path in a nested dict, skipping empty values."""
    if _is_empty(value):
        return
    *parents, leaf = path.split(".")
    for key in parents:
        doc = doc.setdefault(key, {})
    doc[leaf] = value


def _compact(d: dict) -> dict:
    return {k: v for k, v in d.items() if not _is_empty(v)}


def _is_empty(value: object) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _dedupe(values) -> list:
    return list(dict.fromkeys(v for v in values if not _is_empty(v)))


def _one_or_many(values: list) -> object:
    return values[0] if len(values) == 1 else values
