"""Index template / ingest pipeline management and bulk indexing into the Feishu audit data stream."""

import hashlib
import json
import sys
from pathlib import Path

import requests

TEMPLATE_NAME = "logs-feishu.audit"
TEMPLATE_PATH = Path(__file__).with_name("index_template.json")
PIPELINE_NAME = "logs-feishu.audit"
PIPELINE_PATH = Path(__file__).with_name("ingest_pipeline.json")
TIMEOUT = 60


class ElasticError(RuntimeError):
    pass


def load_resource(path: Path) -> dict:
    """Load a template/pipeline body and stamp a hash of its content into _meta.

    The hash catches edits that forgot to bump "version"; Elasticsearch
    normalizes stored bodies, so diffing the returned body is unreliable.
    """
    body = json.loads(path.read_text(encoding="utf-8"))
    canonical = json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    body.setdefault("_meta", {})["content_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
    return body


class Elastic:
    def __init__(self, url: str, api_key: str) -> None:
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": f"ApiKey {api_key}", "Content-Type": "application/json"}
        )

    def request(self, method: str, path: str, ok: tuple[int, ...] = (), **kwargs) -> requests.Response:
        resp = self.session.request(method, self.url + path, timeout=TIMEOUT, **kwargs)
        if resp.status_code >= 300 and resp.status_code not in ok:
            raise ElasticError(f"{method} {path} -> {resp.status_code}: {resp.text[:500]}")
        return resp

    def ensure_resources(self) -> None:
        """Sync the ingest pipeline, then the index template that references it."""
        self.ensure_ingest_pipeline()
        self.ensure_index_template()

    def ensure_ingest_pipeline(self) -> bool:
        """Push the ingest pipeline if the cluster's copy is missing or stale.

        Pipeline changes apply to the next document indexed, so no rollover.
        """
        desired = load_resource(PIPELINE_PATH)
        resp = self.request("GET", f"/_ingest/pipeline/{PIPELINE_NAME}", ok=(404,))
        current = resp.json().get(PIPELINE_NAME) if resp.status_code == 200 else None
        if not self._needs_push("ingest pipeline", PIPELINE_NAME, current, desired):
            return False
        self.request("PUT", f"/_ingest/pipeline/{PIPELINE_NAME}", json=desired)
        self._log_push("ingest pipeline", PIPELINE_NAME, current, desired)
        return True

    def ensure_index_template(self) -> bool:
        """Push the index template if the cluster's copy is missing or stale.

        When pushed, every existing data stream matched by the template is
        rolled over so new documents get the new mappings and settings.
        """
        desired = load_resource(TEMPLATE_PATH)
        resp = self.request("GET", f"/_index_template/{TEMPLATE_NAME}", ok=(404,))
        current = None
        if resp.status_code == 200:
            current = resp.json()["index_templates"][0]["index_template"]
        if not self._needs_push("index template", TEMPLATE_NAME, current, desired):
            return False
        self.request("PUT", f"/_index_template/{TEMPLATE_NAME}", json=desired)
        self._log_push("index template", TEMPLATE_NAME, current, desired)

        patterns = ",".join(desired["index_patterns"])
        resp = self.request("GET", f"/_data_stream/{patterns}", ok=(404,))
        streams = resp.json().get("data_streams", []) if resp.status_code == 200 else []
        for stream in streams:
            name = stream["name"]
            self.request("POST", f"/{name}/_rollover")
            print(f"Rolled over data stream {name}", file=sys.stderr)
        return True

    @staticmethod
    def _needs_push(kind: str, name: str, current: dict | None, desired: dict) -> bool:
        desired_version = desired["version"]
        current_version = current.get("version") if current else None
        current_hash = (current.get("_meta") or {}).get("content_hash") if current else None
        if current_version == desired_version and current_hash == desired["_meta"]["content_hash"]:
            print(f"The {kind} {name} v{desired_version} is up to date", file=sys.stderr)
            return False
        if current_version is not None and current_version > desired_version:
            raise ElasticError(
                f"Cluster has {kind} {name} v{current_version}, newer than this script's "
                f"v{desired_version}; refusing to downgrade. Update the script."
            )
        return True

    @staticmethod
    def _log_push(kind: str, name: str, current: dict | None, desired: dict) -> None:
        previous = f"v{current.get('version')}" if current else "none"
        print(f"Pushed {kind} {name} ({previous} -> v{desired['version']})", file=sys.stderr)

    def latest_timestamp(self, data_stream: str) -> int | None:
        """Newest @timestamp in the data stream as unix seconds, or None if it's empty/missing."""
        resp = self.request(
            "POST",
            f"/{data_stream}/_search",
            ok=(404,),
            json={"size": 0, "aggs": {"latest": {"max": {"field": "@timestamp"}}}},
        )
        if resp.status_code == 404:
            return None
        value = resp.json()["aggregations"]["latest"]["value"]
        return None if value is None else int(value // 1000)

    def bulk_create(self, data_stream: str, docs: list[dict]) -> tuple[int, int]:
        """Index docs with op_type=create, using event.id as _id.

        Returns (created, duplicates). A duplicate is a 409 from a document
        already present in the current backing index.
        """
        lines = []
        for doc in docs:
            lines.append(json.dumps({"create": {"_index": data_stream, "_id": doc["event"]["id"]}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
        body = ("\n".join(lines) + "\n").encode("utf-8")
        result = self.request(
            "POST", "/_bulk", data=body, headers={"Content-Type": "application/x-ndjson"}
        ).json()

        created = duplicates = 0
        failures = []
        for item in result["items"]:
            outcome = item["create"]
            if outcome["status"] < 300:
                created += 1
            elif outcome["status"] == 409:
                duplicates += 1
            else:
                failures.append(outcome)
        if failures:
            raise ElasticError(
                f"{len(failures)} of {len(docs)} documents failed; first error: "
                f"{json.dumps(failures[0].get('error'), ensure_ascii=False)}"
            )
        return created, duplicates
