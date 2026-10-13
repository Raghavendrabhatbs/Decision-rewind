from __future__ import annotations

from typing import Any, Dict

from backend.app.provenance.graph import provenance_paths_for_features
from backend.app.services.dataset_store import DatasetStore
from backend.app.services.universal_log import UniversalLog


def _event_state_for_ai(state: Dict[str, Any], dataset_source: str) -> Dict[str, Any]:
    if dataset_source != "precinct6":
        return state
    source_record = state.get("source_record")
    if not isinstance(source_record, dict):
        source_record = {}
    allowed_source_fields = (
        "timestamp",
        "event_time",
        "timestamp_source",
        "origin",
        "org_id",
        "artifact_id",
        "message_type",
        "stream_name",
        "src_ip",
        "dst_ip",
        "src_host",
        "dst_host",
        "username",
        "action",
        "severity",
        "label_binary",
        "label_confidence",
        "suspicion_score",
        "disposition",
        "disposition_category",
    )
    bounded_source_record = {
        key: source_record[key]
        for key in allowed_source_fields
        if key in source_record
    }
    message = source_record.get("message_sanitized")
    if isinstance(message, str):
        bounded_source_record["message_sanitized_excerpt"] = message[:1_200]
        bounded_source_record["message_sanitized_truncated"] = len(message) > 1_200
    return {
        key: value
        for key, value in state.items()
        if key != "source_record"
    } | {"source_record_summary": bounded_source_record}


def build_llm_evidence(
    question: str,
    dataset_store: DatasetStore,
    universal_log: UniversalLog,
    dataset_id: str | None = None,
    experiment_id: str | None = None,
    event_id: str | None = None,
    correction_id: str | None = None,
    decision_id: str | None = None,
) -> Dict[str, Any]:
    dataset = dataset_store.get_dataset(dataset_id) if dataset_id else None
    if experiment_id and dataset is None:
        dataset = dataset_store.get_dataset_by_experiment_id(experiment_id)
    if dataset_id and dataset is None:
        raise LookupError("Experiment dataset not found.")
    if experiment_id and dataset is None:
        raise LookupError("Experiment not found.")

    evidence: Dict[str, Any] = {
        "question": question,
        "authority": {
            "persisted_database_state": "authoritative",
            "frozen_model_and_counterfactual_replay": "authoritative",
            "deterministic_verification": "authoritative",
            "provenance": "dependency evidence, not proof of a changed decision",
            "universal_logs": "supporting temporal evidence, may be partial",
            "llm": "explanation only; cannot approve or execute recovery",
        },
        "experiment": None,
        "event": None,
        "correction": None,
        "decisions": None,
        "affected_decisions": [],
        "provenance": None,
        "recovery": None,
        "verification": None,
        "workflow_audit": [],
    }
    references = {
        key: value
        for key, value in {
            "dataset_id": dataset["dataset_id"] if dataset else dataset_id,
            "experiment_id": dataset.get("experiment_id") if dataset else experiment_id,
            "event_id": event_id,
            "correction_id": correction_id,
            "decision_id": decision_id,
            "model_version": dataset.get("model_version") if dataset else None,
            "source_revision": dataset.get("source_revision") if dataset else None,
        }.items()
        if value
    }

    audit = []
    if dataset:
        evidence["experiment"] = {
            key: dataset.get(key)
            for key in (
                "dataset_id",
                "experiment_id",
                "seed",
                "record_count",
                "training_status",
                "workflow_status",
                "model_id",
                "model_version",
                "training_dataset_id",
                "training_record_count",
                "trained_at",
                "dataset_source",
                "source_revision",
                "mapping_version",
                "decision_context",
            )
        }
        manifest = dataset.get("source_manifest", {})
        if dataset.get("dataset_source") == "precinct6" and isinstance(manifest, dict):
            evidence["experiment"]["source_dataset"] = {
                key: manifest.get(key)
                for key in (
                    "repository",
                    "version",
                    "license",
                    "imported_record_count",
                    "experiment_record_count",
                    "source_label_distribution",
                    "label_semantics",
                    "decision_context_note",
                )
            }
        audit = dataset_store.list_audit(dataset["dataset_id"], limit=100)

    if correction_id:
        correction = dataset_store.get_correction(correction_id)
        if correction is None or (dataset and correction["dataset_id"] != dataset["dataset_id"]):
            raise LookupError("Correction not found in this experiment.")
        evidence["correction"] = {
            key: correction.get(key)
            for key in ("correction_id", "dataset_id", "event_id", "changes", "status", "created_at")
        }
        event_id = event_id or correction["event_id"]
        references["correction_id"] = correction_id
        references["event_id"] = event_id

    if dataset and event_id:
        event = dataset_store.get_event(dataset["dataset_id"], event_id)
        if event is None:
            raise LookupError("Event not found in this experiment.")
        evidence["event"] = {
            "event_id": event_id,
            "historical_state": _event_state_for_ai(
                event["original_state"],
                dataset.get("dataset_source", "synthetic"),
            ),
            "current_state": _event_state_for_ai(
                event["current_state"],
                dataset.get("dataset_source", "synthetic"),
            ),
        }
        historical = {}
        current = {}
        counterfactual = {}
        for item in event["decisions"]:
            key = item["decision_id"]
            historical[key] = item["historical_output"]
            current[key] = item["current_output"]
            counterfactual[key] = item["counterfactual_output"]

        relevant_audit = [
            row for row in audit
            if row["event_id"] == event_id
        ]
        replay = next(
            (row["details"] for row in relevant_audit if row["operation"] == "COUNTERFACTUAL_REPLAYED"),
            {},
        )
        replay_impacts = {
            item["decision_id"]: item
            for item in replay.get("decision_impacts", [])
            if isinstance(item, dict) and item.get("decision_id")
        }
        for key, item in replay_impacts.items():
            counterfactual[key] = item.get("counterfactual_output", counterfactual.get(key))
        evidence["decisions"] = {
            "historical": historical,
            "current": current,
            "counterfactual": counterfactual,
        }
        evidence["affected_decisions"] = [
            key for key in historical
            if counterfactual.get(key) is not None and historical[key] != counterfactual[key]
        ]
        if decision_id:
            evidence["selected_decision"] = {
                "decision_id": decision_id,
                "historical": historical.get(decision_id),
                "current": current.get(decision_id),
                "counterfactual": counterfactual.get(decision_id),
                "impact": replay_impacts.get(decision_id),
            }

        changes = (evidence.get("correction") or {}).get("changes", [])
        features = [item["feature"] for item in changes if isinstance(item, dict) and item.get("feature")]
        evidence["provenance"] = dataset_store.get_graph(dataset["dataset_id"], features or None)
        evidence["provenance_paths"] = provenance_paths_for_features(features or None)
        evidence["workflow_audit"] = [
            {
                "timestamp": row["timestamp"],
                "operation": row["operation"],
                "details": row["details"],
            }
            for row in reversed(relevant_audit[:50])
        ]
        evidence["recovery"] = next(
            (row["details"] for row in relevant_audit if row["operation"] == "RECOVERED"),
            None,
        )
        evidence["verification"] = next(
            (row["details"] for row in relevant_audit if row["operation"] == "VERIFIED"),
            None,
        )

    evidence["universal_log_context"] = universal_log.context_for_ai(
        question,
        references=references,
        filters=references,
        event_limit=12,
        context_limit=6000,
    )
    return evidence
