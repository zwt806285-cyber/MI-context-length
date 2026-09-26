#!/usr/bin/env python3
"""Re-audit frozen PredictedMI OOF inputs and report descriptive performance.

This analysis is retrospective; it does not turn the performance intervals or
calibration estimate into prespecified confirmatory tests. No transcript text is
written to the output files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
from pathlib import Path
from datetime import datetime, timezone

LABELS = ("CT", "ST", "Neutral")
MODEL = "microsoft/deberta-v3-base"
REVISION = "8ccc9b6f36199bec6961081d44eb72fb3f7353f3"
SEED = 20260908
B = 5000
BOOT_SEED = 42
PATHS = {
    "oof": "inputs/oof/predictions.jsonl",
    "gold": "inputs/oof/gold_units.jsonl",
    "fold_transcripts": "inputs/oof/fold_transcripts.jsonl",
    "fold_units": "inputs/oof/fold_units.jsonl",
    "provenance": "inputs/oof/training_provenance.json",
    "manifest": "protocols/predicted_mi/model_manifest.json",
    "training_protocol": "protocols/predicted_mi/pretraining/training_protocol_manifest.json",
    "frozen_metrics": "protocols/predicted_mi/oof_metrics.json",
    "frozen_audit": "protocols/predicted_mi/oof_integrity_audit.json",
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def canonical_hash(value) -> str:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def rows(path: Path):
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def read(path: Path):
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def artifact(path: Path, root: Path, data=None):
    s = path.stat()
    item = {"path": str(path.resolve()), "relative_path": str(path.relative_to(root)).replace("\\", "/"),
            "bytes": s.st_size, "modified_utc": datetime.fromtimestamp(s.st_mtime, timezone.utc).isoformat(),
            "sha256": sha(path), "format": path.suffix.lstrip(".")}
    if data is not None:
        item["records" if isinstance(data, list) else "top_level_keys"] = (
            len(data) if isinstance(data, list) else sorted(data.keys()))
        if isinstance(data, list) and data:
            item["fields"] = sorted(data[0].keys())
    return item


def summarize(cm, bins):
    n = sum(sum(row) for row in cm)
    require(n > 0, "empty metric denominator")
    diag = [cm[i][i] for i in range(3)]
    gold = [sum(cm[i]) for i in range(3)]
    pred = [sum(cm[i][j] for i in range(3)) for j in range(3)]
    accuracy = sum(diag) / n
    balanced = sum(diag[i] / gold[i] if gold[i] else 0.0 for i in range(3)) / 3
    f1 = [2 * diag[i] / (gold[i] + pred[i]) if gold[i] + pred[i] else 0.0
          for i in range(3)]
    numerator = sum(diag) * n - sum(gold[i] * pred[i] for i in range(3))
    denominator = math.sqrt((n * n - sum(v * v for v in pred)) *
                            (n * n - sum(v * v for v in gold)))
    mcc = numerator / denominator if denominator else 0.0
    ece = sum(abs(row[1] - row[2]) for row in bins) / n
    return {"accuracy": accuracy, "majority_accuracy": gold[2] / n,
            "accuracy_difference": accuracy - gold[2] / n,
            "balanced_accuracy": balanced, "macro_f1": sum(f1) / 3, "mcc": mcc,
            "top_label_ece_10_equal_width": ece, "class_f1": f1}


def percentile_type7(values, proportion):
    ordered = sorted(values)
    position = (len(ordered) - 1) * proportion
    low = math.floor(position)
    fraction = position - low
    return ordered[low] * (1 - fraction) + ordered[min(low + 1, len(ordered) - 1)] * fraction


def main(root: Path, out: Path) -> None:
    root = root.resolve()
    path = {k: root / v for k, v in PATHS.items()}
    require(all(p.is_file() for p in path.values()), "one or more frozen inputs are missing")
    data = {k: (rows(p) if p.suffix == ".jsonl" else read(p)) for k, p in path.items()}
    manifest = data["manifest"]
    provenance = data["provenance"]
    protocol = data["training_protocol"]
    require(manifest["status"] == "FROZEN", "manifest not frozen")
    require(manifest["model_name"] == MODEL and manifest["model_revision"] == REVISION,
            "frozen model identity mismatch")
    require(sha(path["oof"]) == manifest["OOF_prediction_sha256"], "OOF SHA256 mismatch")
    require(sha(path["fold_units"]) == manifest["fold_artifact_sha256"], "unit fold SHA256 mismatch")
    require(sha(path["training_protocol"]) == manifest["pretraining_protocol_sha256"],
            "training protocol SHA256 mismatch")
    require(sha(path["fold_transcripts"]) == manifest["parents"][PATHS["fold_transcripts"]],
            "transcript fold SHA256 mismatch")
    for key in ("oof", "gold", "provenance"):
        rel = PATHS[key]
        require(sha(path[key]) == manifest["artifact_hashes"][rel], f"frozen SHA256 mismatch: {key}")
    require(provenance["protocol_sha256"] == sha(path["training_protocol"]),
            "provenance protocol SHA256 mismatch")
    config = protocol["config"]
    require(config["model_name"] == MODEL and config["model_revision"] == REVISION,
            "training model config mismatch")
    require(config["n_splits"] == 5 and config["training"]["global_seed"] == SEED
            and config["training"]["epochs"] == 4, "training split/seed/epoch mismatch")
    require(config["prediction_rule"] == "argmax", "prediction rule mismatch")

    oof, gold, unit_fold, transcript_fold = (data[x] for x in
                                             ("oof", "gold", "fold_units", "fold_transcripts"))
    require(len(oof) == len(gold) == len(unit_fold) == 4817, "client-unit count mismatch")
    require(len(transcript_fold) == 133, "transcript count mismatch")
    def unique_map(items, key):
        result = {r[key]: r for r in items}
        require(len(result) == len(items), f"duplicate {key}")
        return result
    gold_by_id = unique_map(gold, "canonical_unit_id")
    fold_by_id = unique_map(unit_fold, "canonical_unit_id")
    transcript_by_id = unique_map(transcript_fold, "transcript_id")
    unique_map(oof, "canonical_unit_id")
    require(set(gold_by_id) == {r["canonical_unit_id"] for r in oof} == set(fold_by_id),
            "stable ID coverage mismatch")
    require(set(transcript_by_id) == {r["transcript_id"] for r in oof},
            "transcript coverage mismatch")
    require(set(provenance["folds"]) == {str(i) for i in range(5)}, "provenance fold set mismatch")
    require(data["frozen_audit"] == {"rows": 4817, "status": "PASS",
             "transcript_leakage": 0, "unique_units": 4817}, "frozen audit summary mismatch")

    per_fold = {i: set() for i in range(5)}
    for t, r in transcript_by_id.items():
        f = int(r["held_out_fold"])
        require(f in per_fold, "unexpected fold ID")
        per_fold[f].add(t)
    all_transcripts = set(transcript_by_id)
    for f in range(5):
        trace = provenance["folds"][str(f)]
        train, held = set(trace["training_transcript_ids"]), set(trace["held_out_transcript_ids"])
        require(trace["status"] == "COMPLETE" and trace["epochs_completed"] == 4,
                f"incomplete fold {f}")
        require(train.isdisjoint(held) and train | held == all_transcripts and held == per_fold[f],
                f"train/held-out transcript leakage or mismatch in fold {f}")
        require(trace["predictor_manifest_sha256"] == sha(path["training_protocol"]),
                f"predictor protocol mismatch in fold {f}")
        require(trace["model_name"] == MODEL and trace["model_revision"] == REVISION
                and trace["training_seed"] == SEED + f, f"model/seed mismatch in fold {f}")

    cluster_conf = {t: [[0] * 3 for _ in range(3)] for t in all_transcripts}
    cluster_bins = {t: [[0.0] * 3 for _ in range(10)] for t in all_transcripts}
    per_fold_count = {f: 0 for f in range(5)}
    for r in oof:
        uid, t, f = r["canonical_unit_id"], r["transcript_id"], int(r["fold_id"])
        g, u = gold_by_id[uid], fold_by_id[uid]
        for key in ("transcript_id", "canonical_position", "text_sha256", "gold_label",
                    "fold_id", "source_utterance_ids"):
            require(r[key] == g[key], f"OOF/gold stable join mismatch: {key}")
        for key in ("transcript_id", "canonical_position", "gold_label", "fold_id"):
            require(r[key] == u[key], f"OOF/unit-fold stable join mismatch: {key}")
        require(f in per_fold and t in per_fold[f], "held-out fold mismatch")
        trace = provenance["folds"][str(f)]
        require(t not in trace["training_transcript_ids"] and t in trace["held_out_transcript_ids"],
                "OOF transcript leakage")
        require(r["predictor_manifest_sha256"] == sha(path["training_protocol"]),
                "row predictor hash mismatch")
        require(r["model_name"] == MODEL and r["model_revision"] == REVISION
                and r["training_seed"] == SEED + f, "OOF row model/seed mismatch")
        train_ids = sorted(trace["training_transcript_ids"], key=int)
        require(r["trained_transcript_ids_sha256"] == canonical_hash(train_ids),
                "OOF row training-transcript SHA256 mismatch")
        probs = [r["prob_change"], r["prob_sustain"], r["prob_neutral"]]
        require(all(isinstance(v, (int, float)) and math.isfinite(v) and 0 <= v <= 1
                    for v in probs) and abs(sum(probs) - 1) < 1e-5,
                "invalid class probabilities")
        require(r["predicted_label"] == LABELS[max(range(3), key=probs.__getitem__)],
                "argmax mismatch")
        require(r["gold_label"] in LABELS, "unexpected gold label")
        gi, pi = LABELS.index(r["gold_label"]), LABELS.index(r["predicted_label"])
        cluster_conf[t][gi][pi] += 1
        confidence = float(max(probs))
        bin_id = min(int(confidence * 10), 9)
        cluster_bins[t][bin_id][0] += 1
        cluster_bins[t][bin_id][1] += float(gi == pi)
        cluster_bins[t][bin_id][2] += confidence
        per_fold_count[f] += 1
    require(sorted(per_fold_count.values()) == sorted([1058, 978, 928, 902, 951]),
            "held-out client-unit counts mismatch")

    clusters = sorted(all_transcripts, key=int)
    cm = [[sum(cluster_conf[t][i][j] for t in clusters) for j in range(3)] for i in range(3)]
    bins = [[sum(cluster_bins[t][k][j] for t in clusters) for j in range(3)] for k in range(10)]
    point = summarize(cm, bins)
    frozen = data["frozen_metrics"]
    require(frozen["n"] == 4817 and cm == frozen["confusion_matrix"],
            "frozen confusion matrix mismatch")
    for key in ("accuracy", "balanced_accuracy", "macro_f1", "mcc"):
        require(abs(float(point[key]) - frozen[key]) < 1e-12, f"frozen metric mismatch: {key}")
    for label, f1 in zip(LABELS, point["class_f1"]):
        require(abs(float(f1) - frozen["per_class"][label]["f1"]) < 1e-12,
                f"frozen F1 mismatch: {label}")

    names = ("accuracy", "majority_accuracy", "accuracy_difference", "balanced_accuracy",
             "macro_f1", "mcc", "top_label_ece_10_equal_width")
    rng = random.Random(BOOT_SEED)
    boot = {name: [] for name in names}
    for _ in range(B):
        replicate_cm = [[0] * 3 for _ in range(3)]
        replicate_bins = [[0.0] * 3 for _ in range(10)]
        for _ in clusters:
            t = clusters[rng.randrange(len(clusters))]
            source_cm, source_bins = cluster_conf[t], cluster_bins[t]
            for i in range(3):
                for j in range(3):
                    replicate_cm[i][j] += source_cm[i][j]
            for k in range(10):
                for j in range(3):
                    replicate_bins[k][j] += source_bins[k][j]
        score = summarize(replicate_cm, replicate_bins)
        for name in names:
            boot[name].append(score[name])
    results = {}
    for name in names:
        lo, hi = (percentile_type7(boot[name], p) for p in (0.025, 0.975))
        results[name] = {"estimate": float(point[name]), "ci95": [float(lo), float(hi)]}
    results["per_class_f1"] = {label: float(v) for label, v in zip(LABELS, point["class_f1"])}
    results["confusion_matrix"] = cm
    results["n_client_units"] = 4817
    results["n_transcript_clusters"] = 133
    results["bootstrap"] = {"replicates": B, "seed": BOOT_SEED,
        "cluster": "transcript_id", "rng": "Python random.Random MT19937",
        "sampling": "133 clusters with replacement per replicate",
        "weighting": "all rows from each sampled cluster, including multiplicity",
        "interval": "2.5th/97.5th percentile; linear/type-7 interpolation"}
    results["ece_definition"] = ("top-label expected calibration error; 10 equal-width confidence bins "
        "[0,.1),[.1,.2),...,[.9,1]; implementation uses min(floor(10*confidence),9); "
        "weighted mean absolute "
        "difference between within-bin accuracy and mean maximum probability")
    results["inference_role"] = "retrospective descriptive OOF performance; not frozen confirmatory inference"

    inventory = {"created_utc": datetime.now(timezone.utc).isoformat(),
        "root": str(root), "artifacts": {k: artifact(path[k], root, data[k]) for k in PATHS},
        "script": {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__).resolve())}}
    audit = {"status": "PASS", "record_count": 4817, "transcript_count": 133,
        "fold_counts": per_fold_count,
        "check_groups": ["frozen manifest identity", "all input SHA256 pins", "training config/model/revision/seed/epochs",
           "stable unit ID bijection", "gold field equality", "unit-fold field equality",
           "transcript-held-out fold assignment", "training/held-out disjointness and coverage",
           "fold provenance protocol hash", "per-row predictor and training-set hashes",
           "finite normalized probabilities", "hard-label argmax", "frozen confusion matrix and point metrics"],
        "note": "Check groups are documented here after OOF freezing; no unsupported claim of 58 prespecified checks."}
    md = "# PredictedMI OOF input and performance audit\n\n"
    md += "Status: **PASS**. The frozen merged OOF contains 4,817 unique client units in 133 held-out transcripts. "
    md += "All stable joins, fold/provenance, SHA256, probability, argmax, and frozen-point-metric checks passed.\n\n"
    md += "This is a retrospective descriptive OOF performance analysis, not a prespecified confirmatory test. "
    md += "The source frozen audit records PASS/4,817/zero leakage but does not enumerate 58 checks.\n\n"
    md += "| Measure | Point | Transcript-cluster bootstrap 95% CI |\n|---|---:|---:|\n"
    for name in names:
        v = results[name]
        md += f"| {name} | {v['estimate']:.6f} | [{v['ci95'][0]:.6f}, {v['ci95'][1]:.6f}] |\n"
    md += "\nECE uses 10 equal-width top-label confidence bins. Intervals use 5,000 paired transcript-cluster "
    md += "resamples (Python MT19937, seed 42) and percentile/type-7 limits. No text or transcript content is emitted.\n"

    out.mkdir(parents=True, exist_ok=True)
    payloads = {"artifact_inventory.json": inventory, "oof_input_manifest.json":
        {"input_audit": audit, "performance": results, "input_sha256":
         {k: inventory["artifacts"][k]["sha256"] for k in PATHS}},
        "oof_input_audit.md": md}
    temp_paths = []
    for name, payload in payloads.items():
        target = out / name
        tmp = out / (name + ".tmp")
        content = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False,
            sort_keys=True, indent=2, allow_nan=False) + "\n"
        with tmp.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if name.endswith(".json"):
            read(tmp)
        temp_paths.append((tmp, target))
    for tmp, target in temp_paths:
        os.replace(tmp, target)
    print(json.dumps({"status": "PASS", "output": str(out), "results": results}, ensure_ascii=False))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", "--root", dest="root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    main(args.root, args.out or args.root / "outputs/oof_audit")
