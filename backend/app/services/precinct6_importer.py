from __future__ import annotations

import hashlib
import json
import math
import os
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from bisect import bisect_right
from typing import Any, Dict, List

import pyarrow as pa
import pyarrow.parquet as parquet

from backend.app.config import DATA_DIR
from backend.app.services.dataset_store import DatasetStore

DATASET_REPOSITORY = "witfoo/precinct6-cybersecurity"
DATASET_REVISION = "96311c2e29611d8ddbf1c0d59f531f6a362b8233"
DATASET_VERSION = "2.1.0"
DATASET_LICENSE = "apache-2.0"
SIGNALS_FILE = "signals/signals.parquet"
SIGNALS_SHA256 = "20d01fd225636e9b95a30bfe88c3c6faeb49e8595d4e784c96ea7fa62c6a746c"
SIGNALS_SIZE = 117_056_748
SIGNALS_ROWS = 2_011_674
MAPPING_VERSION = "precinct6-signals-to-decision-context-v1"
BATCH_SIZE = 8_192

SIGNAL_COLUMNS = [
    "timestamp",
    "event_time",
    "timestamp_source",
    "origin",
    "org_id",
    "artifact_id",
    "message_type",
    "stream_name",
    "pipeline",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "src_host",
    "dst_host",
    "username",
    "action",
    "severity",
    "vendor_code",
    "message_sanitized",
    "label_binary",
    "label_confidence",
    "attack_techniques",
    "attack_tactics",
    "defense_techniques",
    "mo_name",
    "suspicion_score",
    "lifecycle_stage",
    "disposition",
    "disposition_category",
    "is_false_positive",
    "status_name",
    "incident_ids",
    "matched_rules",
    "set_roles",
    "product_name",
    "vendor_name",
]
VALID_LABELS = {"benign", "suspicious", "malicious"}
_SIMULATED_ASSET_CRITICALITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def source_metadata() -> Dict[str, Any]:
    return {
        "repository": DATASET_REPOSITORY,
        "version": DATASET_VERSION,
        "revision": DATASET_REVISION,
        "license": DATASET_LICENSE,
        "file": SIGNALS_FILE,
        "file_sha256": SIGNALS_SHA256,
        "file_size_bytes": SIGNALS_SIZE,
        "declared_rows": SIGNALS_ROWS,
        "schema": SIGNAL_COLUMNS,
        "label_semantics": (
            "WitFoo Precinct automated incident-correlation labels; not independently "
            "analyst-verified ground truth for the five DECISION-REWIND decisions."
        ),
        "reference": f"https://huggingface.co/datasets/{DATASET_REPOSITORY}/tree/{DATASET_REVISION}",
    }


class Precinct6Importer:
    def __init__(self, dataset_store: DatasetStore):
        self.dataset_store = dataset_store
        self.file_path = (
            DATA_DIR
            / "precinct6"
            / DATASET_REVISION
            / "signals.parquet"
        )

    def status(self) -> Dict[str, Any]:
        status = self.dataset_store.get_precinct6_import(DATASET_REVISION)
        cache_valid = bool(status and status["status"] == "READY" and self.cache_valid())
        return {
            **source_metadata(),
            "status": status["status"] if status else "NOT_IMPORTED",
            "cache_valid": cache_valid,
            "expected_rows": status["expected_rows"] if status else SIGNALS_ROWS,
            "parsed_rows": status["parsed_rows"] if status else 0,
            "accepted_rows": status["accepted_rows"] if status else 0,
            "skipped_rows": status["skipped_rows"] if status else 0,
            "rejected_rows": status["rejected_rows"] if status else 0,
            "label_distribution": status["label_distribution"] if status else {},
            "error": status["error"] if status else None,
            "updated_at": status["updated_at"] if status else None,
        }

    def start(self) -> bool:
        current = self.dataset_store.get_precinct6_import(DATASET_REVISION)
        if current and current["status"] == "READY" and not self.cache_valid():
            self.dataset_store.set_precinct6_import_status(
                DATASET_REVISION,
                "FAILED",
                error="The local Precinct6 cache is missing or failed its pinned SHA-256 check.",
            )
        return self.dataset_store.start_precinct6_import(
            DATASET_REVISION,
            SIGNALS_ROWS,
            str(self.file_path),
        )

    def run(self, log: Any) -> Dict[str, Any]:
        try:
            return self._run(log)
        except Exception as error:
            self.dataset_store.set_precinct6_import_status(
                DATASET_REVISION,
                "FAILED",
                error=str(error),
            )
            log.record(
                "dataset.import.failed",
                "precinct6_importer",
                {"source_revision": DATASET_REVISION, "error": str(error)},
            )
            raise

    def _run(self, log: Any) -> Dict[str, Any]:
        if not self.file_path.is_file() or self._sha256(self.file_path) != SIGNALS_SHA256:
            self.dataset_store.set_precinct6_import_status(DATASET_REVISION, "DOWNLOADING")
            self._download()

        self.dataset_store.set_precinct6_import_status(DATASET_REVISION, "VERIFYING")
        source = parquet.ParquetFile(self.file_path)
        actual_schema = [
            {"name": field.name, "type": str(field.type)}
            for field in source.schema_arrow
        ]
        actual_columns = [field["name"] for field in actual_schema]
        if actual_columns != SIGNAL_COLUMNS:
            raise ValueError(
                "Precinct6 Parquet schema does not match the pinned 38-column schema. "
                f"Expected {SIGNAL_COLUMNS}; received {actual_columns}."
            )
        arrow_schema = source.schema_arrow
        required_strings = ("artifact_id", "org_id", "label_binary")
        if any(not (pa.types.is_string(arrow_schema.field(name).type)
                    or pa.types.is_large_string(arrow_schema.field(name).type))
               for name in required_strings):
            raise ValueError("Precinct6 identifier and label columns must have a string Parquet type.")
        required_numbers = ("timestamp", "event_time", "label_confidence", "suspicion_score")
        if any(not pa.types.is_floating(arrow_schema.field(name).type) for name in required_numbers):
            raise ValueError("Precinct6 timestamp and confidence columns must have a floating-point Parquet type.")
        if not pa.types.is_boolean(arrow_schema.field("is_false_positive").type):
            raise ValueError("Precinct6 is_false_positive must have a boolean Parquet type.")
        if source.metadata.num_rows != SIGNALS_ROWS:
            raise ValueError(
                f"Precinct6 Parquet declares {source.metadata.num_rows} rows; "
                f"the pinned metadata requires {SIGNALS_ROWS}."
            )

        self.dataset_store.set_precinct6_import_status(
            DATASET_REVISION,
            "IMPORTING",
            file_sha256=SIGNALS_SHA256,
            schema=actual_schema,
        )
        labels: Counter[str] = Counter()
        parsed_rows = 0
        rejected_rows = 0
        pending: List[Dict[str, Any]] = []
        for batch in source.iter_batches(
            batch_size=BATCH_SIZE,
            columns=["timestamp", "org_id", "artifact_id", "label_binary"],
        ):
            for row in batch.to_pylist():
                row_index = parsed_rows
                parsed_rows += 1
                artifact_id = row.get("artifact_id")
                label = row.get("label_binary")
                timestamp = row.get("timestamp")
                org_id = row.get("org_id")
                if (
                    not isinstance(artifact_id, str)
                    or not artifact_id
                    or label not in VALID_LABELS
                    or not isinstance(org_id, str)
                    or not org_id
                    or not isinstance(timestamp, (int, float))
                    or not math.isfinite(float(timestamp))
                ):
                    rejected_rows += 1
                    continue
                labels[label] += 1
                pending.append({
                    "artifact_id": artifact_id,
                    "row_index": row_index,
                    "timestamp": float(timestamp),
                    "org_id": org_id,
                    "label_binary": label,
                })
                if len(pending) >= BATCH_SIZE:
                    self.dataset_store.import_precinct6_batch(
                        DATASET_REVISION,
                        pending,
                        len(pending),
                        0,
                    )
                    pending.clear()
                    if parsed_rows % (BATCH_SIZE * 16) < BATCH_SIZE:
                        log.record(
                            "dataset.import.progress",
                            "precinct6_importer",
                            {
                                "source_revision": DATASET_REVISION,
                                "parsed_rows": parsed_rows,
                                "expected_rows": SIGNALS_ROWS,
                            },
                        )
            if pending and len(pending) >= BATCH_SIZE:
                self.dataset_store.import_precinct6_batch(
                    DATASET_REVISION,
                    pending,
                    len(pending),
                    0,
                )
                pending.clear()

        if pending:
            self.dataset_store.import_precinct6_batch(
                DATASET_REVISION,
                pending,
                len(pending),
                0,
            )
        result = self.dataset_store.finish_precinct6_import(
            DATASET_REVISION,
            parsed_rows,
            dict(labels),
            rejected_rows=rejected_rows,
        )
        log.record(
            "dataset.import.completed",
            "precinct6_importer",
            {
                "source_revision": DATASET_REVISION,
                "dataset_version": DATASET_VERSION,
                "parsed_rows": parsed_rows,
                "accepted_rows": result["accepted_rows"],
                "skipped_rows": result["skipped_rows"],
                "rejected_rows": result["rejected_rows"],
                "label_distribution": result["label_distribution"],
                "file_sha256": SIGNALS_SHA256,
            },
        )
        return self.status()

    def create_experiment_events(
        self,
        selected: List[Dict[str, Any]],
        seed: int,
    ) -> List[Dict[str, Any]]:
        if not self.cache_valid():
            raise ValueError("The local Precinct6 cache is missing or failed its pinned SHA-256 check; re-import the source.")
        source = parquet.ParquetFile(self.file_path)
        target_by_row = {record["row_index"]: record for record in selected}
        group_starts: List[int] = []
        next_row = 0
        for index in range(source.metadata.num_row_groups):
            group_starts.append(next_row)
            next_row += source.metadata.row_group(index).num_rows
        group_targets: Dict[int, Dict[int, Dict[str, Any]]] = {}
        for row_index, record in target_by_row.items():
            group = bisect_right(group_starts, row_index) - 1
            group_targets.setdefault(group, {})[row_index] = record

        events: List[Dict[str, Any]] = []
        for group_index, offsets in group_targets.items():
            batch_start = group_starts[group_index]
            for batch in source.iter_batches(
                batch_size=1_024,
                row_groups=[group_index],
                columns=SIGNAL_COLUMNS,
            ):
                batch_rows = batch.to_pylist()
                for offset, row in enumerate(batch_rows):
                    row_index = batch_start + offset
                    selected_record = offsets.get(row_index)
                    if selected_record is None:
                        continue
                    source_record = _json_safe(row)
                    if source_record.get("artifact_id") != selected_record["artifact_id"]:
                        raise ValueError("Precinct6 source row changed after import; refusing to create an experiment.")
                    events.append(map_precinct6_record(
                        source_record,
                        seed,
                        selected_record["artifact_id"],
                        row_index,
                    ))
                batch_start += len(batch_rows)
        events.sort(key=lambda event: event["source_row_index"])
        if len(events) != len(selected):
            raise ValueError(
                f"Could not retrieve every selected Precinct6 record: expected {len(selected)}, found {len(events)}."
            )
        return events

    def cache_valid(self) -> bool:
        return (
            self.file_path.is_file()
            and self.file_path.stat().st_size == SIGNALS_SIZE
            and self._sha256(self.file_path) == SIGNALS_SHA256
        )

    def _download(self) -> None:
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = self.file_path.with_suffix(".parquet.part")
        url = (
            f"https://huggingface.co/datasets/{DATASET_REPOSITORY}/resolve/"
            f"{DATASET_REVISION}/{SIGNALS_FILE}?download=true"
        )
        request = urllib.request.Request(url, headers={"User-Agent": "Decision-Rewind/1.0"})
        digest = hashlib.sha256()
        size = 0
        try:
            with urllib.request.urlopen(request, timeout=120) as response, temporary_path.open("wb") as output:
                while chunk := response.read(1024 * 1024):
                    output.write(chunk)
                    digest.update(chunk)
                    size += len(chunk)
            if size != SIGNALS_SIZE or digest.hexdigest() != SIGNALS_SHA256:
                raise ValueError(
                    "Downloaded Precinct6 Parquet does not match the pinned size and SHA-256."
                )
            os.replace(temporary_path, self.file_path)
        except Exception:
            if temporary_path.exists():
                temporary_path.unlink()
            raise

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()


def map_precinct6_record(
    source_record: Dict[str, Any],
    seed: int,
    artifact_id: str,
    row_index: int | None = None,
) -> Dict[str, Any]:
    simulation_seed = hashlib.sha256(f"{seed}:{artifact_id}".encode("utf-8")).digest()
    source_timestamp = _finite_number(source_record.get("timestamp"))
    event_time = _finite_number(source_record.get("event_time"))
    display_timestamp = event_time if event_time is not None else source_timestamp
    if display_timestamp is None:
        raise ValueError(f"Precinct6 record {artifact_id} has no usable timestamp.")
    timestamp = datetime.fromtimestamp(display_timestamp, timezone.utc).isoformat()
    src_ip = source_record.get("src_ip") or ""
    username = source_record.get("username") or "UNAVAILABLE"
    host = source_record.get("dst_host") or source_record.get("src_host") or "UNAVAILABLE"
    simulated_features = {
        "failed_logins": simulation_seed[0] % 21,
        "geo_anomaly": bool(simulation_seed[1] % 2),
        "asset_criticality": _SIMULATED_ASSET_CRITICALITIES[
            simulation_seed[2] % len(_SIMULATED_ASSET_CRITICALITIES)
        ],
        "threat_intel_score": round(int.from_bytes(simulation_seed[3:5], "big") / 65_535, 4),
        "previous_alerts": simulation_seed[5] % 11,
    }
    login_time_origin = "event_time" if event_time is not None else "timestamp"
    return {
        "event_id": f"P6-{artifact_id}",
        "source_label": source_record.get("label_binary"),
        "timestamp": timestamp,
        "user_id": username,
        "source_ip": src_ip,
        "failed_logins": simulated_features["failed_logins"],
        "login_hour": datetime.fromtimestamp(display_timestamp, timezone.utc).hour,
        "geo_anomaly": simulated_features["geo_anomaly"],
        "asset_id": host,
        "asset_type": "UNAVAILABLE",
        "asset_criticality": simulated_features["asset_criticality"],
        "threat_intel_score": simulated_features["threat_intel_score"],
        "previous_alerts": simulated_features["previous_alerts"],
        "decision_outputs": {},
        "source_record_id": artifact_id,
        "source_row_index": row_index,
        "source_record": source_record,
        "source_provenance": {
            "dataset": DATASET_REPOSITORY,
            "dataset_version": DATASET_VERSION,
            "dataset_revision": DATASET_REVISION,
            "license": DATASET_LICENSE,
            "label_binary": source_record.get("label_binary"),
            "label_semantics": "Automated Precinct correlation label; not D1-D5 ground truth.",
            "mapping_version": MAPPING_VERSION,
            "decision_context": "simulated_context",
        },
        "feature_provenance": {
            "event_id": {"origin": "source", "source_field": "artifact_id"},
            "timestamp": {
                "origin": "derived",
                "source_field": login_time_origin,
                "note": "UTC display time; event_time is used when present, otherwise Precinct ingest/correlation timestamp.",
            },
            "user_id": {"origin": "source", "source_field": "username"},
            "source_ip": {"origin": "source", "source_field": "src_ip"},
            "failed_logins": {"origin": "simulated", "note": "Synthetic decision-context feature; not present in Precinct6."},
            "login_hour": {
                "origin": "derived",
                "source_field": login_time_origin,
                "note": "UTC hour derived from the selected Precinct timestamp; not an authentication outcome.",
            },
            "geo_anomaly": {"origin": "simulated", "note": "Synthetic decision-context feature; not present in Precinct6."},
            "asset_id": {"origin": "source", "source_field": "dst_host or src_host"},
            "asset_type": {"origin": "unavailable", "note": "Precinct6 does not supply this field."},
            "asset_criticality": {"origin": "simulated", "note": "Synthetic decision-context feature; not present in Precinct6."},
            "threat_intel_score": {"origin": "simulated", "note": "Synthetic decision-context feature; not the Precinct suspicion_score."},
            "previous_alerts": {"origin": "simulated", "note": "Synthetic decision-context feature; not present in Precinct6."},
        },
    }


def _finite_number(value: Any) -> float | None:
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return None


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if hasattr(value, "item"):
        return _json_safe(value.item())
    return value
