import hashlib
from collections import Counter

import pyarrow as pa
import pyarrow.parquet as pq
import pytest

from backend.app.services import precinct6_importer as importer_module
from backend.app.services.dataset_store import DatasetStore
from backend.app.services.precinct6_importer import (
    MAPPING_VERSION,
    SIGNAL_COLUMNS,
    Precinct6Importer,
    map_precinct6_record,
)
from backend.app.services.universal_log import UniversalLog


def _write_fixture(path, record_count):
    rows = []
    for index in range(record_count):
        row = {
            column: f"{column}-{index}"
            for column in SIGNAL_COLUMNS
        }
        row.update({
            "timestamp": 1_722_000_000.0 + index,
            "event_time": 1_722_000_100.0 + index if index % 2 else None,
            "timestamp_source": "artifact.timeuuid",
            "origin": "live",
            "org_id": f"ORG-{index % 4:04d}",
            "artifact_id": f"ARTIFACT-{index:06d}",
            "src_ip": f"198.51.100.{index % 255}",
            "dst_host": f"HOST-{index:04d}",
            "username": f"USER-{index:04d}",
            "label_binary": ("benign", "suspicious", "malicious")[index % 3],
            "label_confidence": 0.8,
            "suspicion_score": 0.2,
            "is_false_positive": False,
        })
        rows.append(row)
    table = pa.Table.from_pylist(rows)
    pq.write_table(table, path, row_group_size=37)
    return rows


def test_precinct6_mapping_keeps_source_labels_separate_from_simulated_decisions():
    source = {
        "artifact_id": "ARTIFACT-1",
        "timestamp": 1_722_000_000.0,
        "event_time": None,
        "src_ip": "198.51.100.2",
        "dst_host": "HOST-22",
        "username": "USER-18",
        "label_binary": "malicious",
        "suspicion_score": 0.0,
    }

    first = map_precinct6_record(source, 42, source["artifact_id"], 17)
    repeated = map_precinct6_record(source, 42, source["artifact_id"], 17)

    assert first == repeated
    assert first["source_label"] == "malicious"
    assert first["source_provenance"]["label_binary"] == "malicious"
    assert first["source_provenance"]["decision_context"] == "simulated_context"
    assert first["feature_provenance"]["failed_logins"]["origin"] == "simulated"
    assert first["feature_provenance"]["login_hour"]["source_field"] == "timestamp"
    assert first["feature_provenance"]["source_ip"]["origin"] == "source"
    assert first["feature_provenance"]["asset_type"]["origin"] == "unavailable"
    assert first["threat_intel_score"] != source["suspicion_score"]
    assert first["source_record"] == source
    assert first["source_row_index"] == 17
    assert MAPPING_VERSION == first["source_provenance"]["mapping_version"]


def test_import_is_incremental_idempotent_and_reserves_fresh_real_experiment_rows(tmp_path, monkeypatch):
    path = tmp_path / "signals.parquet"
    source_rows = _write_fixture(path, 200)
    file_digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(importer_module, "SIGNALS_ROWS", len(source_rows))
    monkeypatch.setattr(importer_module, "SIGNALS_SIZE", path.stat().st_size)
    monkeypatch.setattr(importer_module, "SIGNALS_SHA256", file_digest)
    monkeypatch.setattr(importer_module, "BATCH_SIZE", 17)

    store = DatasetStore(tmp_path / "workbench.db")
    importer = Precinct6Importer(store)
    importer.file_path = path
    assert importer.start()

    status = importer.run(UniversalLog(tmp_path / "universal_log.jsonl"))
    assert status["status"] == "READY"
    assert status["expected_rows"] == status["parsed_rows"] == status["accepted_rows"] == 200
    assert status["rejected_rows"] == status["skipped_rows"] == 0
    assert status["label_distribution"] == dict(Counter(row["label_binary"] for row in source_rows))

    selected = store.sample_precinct6_records(importer_module.DATASET_REVISION, 200, 7)
    events = importer.create_experiment_events(selected, 7)
    assert len(events) == 200
    assert len({event["source_record_id"] for event in events}) == 200
    assert all(len(event["source_record"]) == 38 for event in events)
    assert all(event["source_label"] == event["source_record"]["label_binary"] for event in events)

    dataset = store.create_dataset(
        "DS-PRECINCT6-TEST",
        7,
        events,
        {
            "model_id": "SOC-MODEL-V1",
            "model_version": "V1",
            "artifact_path": str(tmp_path / "model.joblib"),
            "training_dataset_id": "TRN-SYNTHETIC-TEST",
        },
        {
            "dataset_source": "precinct6",
            "source_revision": importer_module.DATASET_REVISION,
            "mapping_version": MAPPING_VERSION,
            "decision_context": "simulated_context",
            "source_manifest": {"repository": importer_module.DATASET_REPOSITORY},
            "source_record_ids": [record["artifact_id"] for record in selected],
        },
    )
    assert dataset["dataset_source"] == "precinct6"
    assert dataset["source_revision"] == importer_module.DATASET_REVISION
    assert dataset["mapping_version"] == MAPPING_VERSION
    predictions = {
        event["event_id"]: {
            "D1": "ALLOW",
            "D2": "LOW",
            "D3": "NORMAL",
            "D4": "MONITOR",
            "D5": "ALLOW",
        }
        for event in events
    }
    trained = store.complete_experiment_training(dataset["dataset_id"], predictions)
    selected_event = store.get_event(dataset["dataset_id"], events[0]["event_id"])
    source_snapshot = selected_event["original_state"]["source_record"]
    next_logins = (selected_event["current_state"]["failed_logins"] + 1) % 21
    correction = store.create_correction(
        dataset["dataset_id"],
        events[0]["event_id"],
        [{"feature": "failed_logins", "new_value": next_logins}],
        evidence="Controlled simulation test with immutable source evidence.",
    )
    counterfactual = {
        item["decision_id"]: item["current_output"]
        for item in selected_event["decisions"]
    }
    impacts = {
        item["decision_id"]: {
            "historical_output": item["historical_output"],
            "current_output": item["current_output"],
            "counterfactual_output": item["current_output"],
            "affected": False,
        }
        for item in selected_event["decisions"]
    }
    rewind = store.complete_rewind(
        correction,
        counterfactual,
        [],
        impacts,
        {"verification": "VERIFIED", "reasons": []},
    )
    after_rewind = store.get_event(dataset["dataset_id"], events[0]["event_id"])
    assert trained["dataset_source"] == "precinct6"
    assert rewind["verification"]["verified"] is True
    assert after_rewind["original_state"]["source_record"] == source_snapshot
    assert after_rewind["current_state"]["source_record"] == source_snapshot
    assert after_rewind["current_state"]["failed_logins"] == next_logins
    with pytest.raises(ValueError, match="only 0 unused records"):
        store.sample_precinct6_records(importer_module.DATASET_REVISION, 1, 8)

    store.set_precinct6_import_status(importer_module.DATASET_REVISION, "FAILED", error="test retry")
    assert importer.start()
    retried = importer.run(UniversalLog(tmp_path / "retry_log.jsonl"))
    assert retried["status"] == "READY"
    assert retried["accepted_rows"] == 200


def test_source_file_schema_mismatch_fails_without_activating_import(tmp_path, monkeypatch):
    path = tmp_path / "signals.parquet"
    pq.write_table(pa.table({"wrong": [1]}), path)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(importer_module, "SIGNALS_SHA256", digest)
    monkeypatch.setattr(importer_module, "SIGNALS_ROWS", 1)
    monkeypatch.setattr(importer_module, "SIGNALS_SIZE", path.stat().st_size)
    store = DatasetStore(tmp_path / "workbench.db")
    importer = Precinct6Importer(store)
    importer.file_path = path
    importer.start()

    with pytest.raises(ValueError, match="schema does not match"):
        importer.run(UniversalLog(tmp_path / "universal_log.jsonl"))

    assert importer.status()["status"] == "FAILED"
    assert importer.status()["accepted_rows"] == 0


def test_experiment_api_rejects_unverified_or_missing_local_cache(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from backend.app import main

    store = DatasetStore(tmp_path / "api-workbench.db")
    monkeypatch.setattr(store, "get_active_model", lambda: {"model_version": "V1"})
    monkeypatch.setattr(main, "dataset_store", store)
    monkeypatch.setattr(
        main,
        "precinct6_importer",
        type("ImporterStatus", (), {
            "status": lambda self: {"status": "READY", "cache_valid": False}
        })(),
    )
    monkeypatch.setattr(main, "universal_log", UniversalLog(tmp_path / "api-log.jsonl"))

    with TestClient(main.app) as client:
        response = client.post("/api/datasets/precinct6")

    assert response.status_code == 409
    assert "not verified and available locally" in response.json()["detail"]
