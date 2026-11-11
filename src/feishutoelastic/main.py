"""Pull the behavior audit log from Feishu and index it into Elasticsearch as ECS.

Reads configuration from .env (or the environment):
  APP_ID, APP_SECRET   Feishu app credentials (required)
  FEISHU_BASE_URL      default https://open.feishu.cn; use
                       https://open.larksuite.com for Lark international tenants
  ES_URL, ES_API_KEY   Elasticsearch endpoint and encoded API key (required
                       unless --dry-run)
  ES_NAMESPACE         data stream namespace, default "default"

Documents go to the data stream logs-feishu.audit-<ES_NAMESPACE>. Before the
first batch is indexed, the ingest pipeline and index template are checked and
pushed if they changed; a template change also rolls the data stream over.

Each run is a single pass meant to be scheduled (e.g. cron). The fetch window
starts at the newest @timestamp already indexed minus OVERLAP_SECONDS, so missed
runs catch up on their own; an empty data stream backfills MAX_LOOKBACK_SECONDS.
Re-fetched entries are skipped because event.id is used as the document _id.
"""

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Iterator
from datetime import UTC, datetime

import requests
from dotenv import load_dotenv

from ecs_transform import DATASET, to_ecs
from elastic import Elastic

DEFAULT_BASE_URL = "https://open.feishu.cn"
TOKEN_PATH = "/open-apis/auth/v3/tenant_access_token/internal"
AUDIT_PATH = "/open-apis/admin/v1/audit_infos"
PAGE_SIZE = 200  # API max
MAX_LOOKBACK_SECONDS = 30 * 24 * 60 * 60  # widest range the audit API accepts
OVERLAP_SECONDS = 10 * 60  # re-fetch window for entries Feishu publishes late
TIMEOUT = 30
BATCH_SIZE = 500
NAMESPACE_PATTERN = re.compile(r"[a-z0-9_.]{1,100}")


class FeishuError(RuntimeError):
    pass


def check(resp: requests.Response) -> dict:
    """Raise on HTTP or Feishu-level errors; return the parsed JSON body."""
    try:
        body = resp.json()
    except ValueError:
        resp.raise_for_status()
        raise FeishuError(f"Non-JSON response: {resp.text[:200]}")
    # Feishu returns a "code" field; 0 means success. Errors may come with non-2xx too.
    if body.get("code", 0) != 0:
        raise FeishuError(f"Feishu API error {body.get('code')}: {body.get('msg')}")
    resp.raise_for_status()
    return body


def get_tenant_access_token(base_url: str, app_id: str, app_secret: str) -> str:
    resp = requests.post(
        base_url + TOKEN_PATH,
        json={"app_id": app_id, "app_secret": app_secret},
        timeout=TIMEOUT,
    )
    return check(resp)["tenant_access_token"]


def iter_audit_logs(
    base_url: str, token: str, oldest_time: int, latest_time: int
) -> Iterator[dict]:
    """Yield every audit log entry in [oldest_time, latest_time] (unix seconds)."""
    headers = {"Authorization": f"Bearer {token}"}
    params: dict[str, str | int] = {
        "oldest": oldest_time,
        "latest": latest_time,
        "page_size": PAGE_SIZE,
    }
    while True:
        resp = requests.get(
            base_url + AUDIT_PATH, headers=headers, params=params, timeout=TIMEOUT
        )
        data = check(resp).get("data", {})
        yield from data.get("items", [])
        if not data.get("has_more"):
            break
        params["page_token"] = data["page_token"]


def batched(docs: Iterator[dict], size: int) -> Iterator[list[dict]]:
    batch: list[dict] = []
    for doc in docs:
        batch.append(doc)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def fmt_time(epoch_seconds: int) -> str:
    return datetime.fromtimestamp(epoch_seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the ECS documents instead of indexing them",
    )
    args = parser.parse_args()

    # Audit logs contain CJK text; the default Windows console encoding can't print it.
    sys.stdout.reconfigure(encoding="utf-8")
    load_dotenv()
    app_id = os.environ.get("APP_ID")
    app_secret = os.environ.get("APP_SECRET")
    if not app_id or not app_secret:
        raise SystemExit("APP_ID and APP_SECRET must be set in .env or the environment")
    base_url = os.environ.get("FEISHU_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    namespace = os.environ.get("ES_NAMESPACE", "default")
    if not NAMESPACE_PATTERN.fullmatch(namespace):
        raise SystemExit(f"ES_NAMESPACE {namespace!r} must match {NAMESPACE_PATTERN.pattern}")
    data_stream = f"logs-{DATASET}-{namespace}"

    es = None
    if not args.dry_run:
        es_url = os.environ.get("ES_URL")
        es_api_key = os.environ.get("ES_API_KEY")
        if not es_url or not es_api_key:
            raise SystemExit("ES_URL and ES_API_KEY must be set (or use --dry-run)")
        es = Elastic(es_url, es_api_key)
        es.ensure_resources()

    now = int(time.time())
    oldest = now - MAX_LOOKBACK_SECONDS
    checkpoint = es.latest_timestamp(data_stream) if es else None
    if checkpoint is not None:
        if checkpoint - OVERLAP_SECONDS < oldest:
            print(
                f"Warning: last indexed entry is {fmt_time(checkpoint)}, older than the "
                f"API's 30-day limit; entries before {fmt_time(oldest)} are skipped",
                file=sys.stderr,
            )
        oldest = max(oldest, checkpoint - OVERLAP_SECONDS)

    token = get_tenant_access_token(base_url, app_id, app_secret)
    entries = iter_audit_logs(base_url, token, oldest, now)
    docs = (to_ecs(entry, namespace) for entry in entries)

    total = created = duplicates = 0
    for batch in batched(docs, BATCH_SIZE):
        total += len(batch)
        if es is None:
            for doc in batch:
                print(json.dumps(doc, ensure_ascii=False, indent=2))
            continue
        batch_created, batch_duplicates = es.bulk_create(data_stream, batch)
        created += batch_created
        duplicates += batch_duplicates

    window = f"{fmt_time(oldest)} .. {fmt_time(now)}"
    if es is None:
        print(f"-- {window}: {total} audit log entries (dry run) --")
    else:
        print(
            f"-- {window}: {total} audit log entries, "
            f"{created} indexed, {duplicates} already present --"
        )


if __name__ == "__main__":
    main()
