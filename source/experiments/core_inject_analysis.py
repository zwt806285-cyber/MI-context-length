from __future__ import annotations

import csv
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path

import numpy as np


from repro_paths import PROJECT_ROOT as ROOT

FREEZE = ROOT / (
    "protocols/"
    "core_inject"
)

PROTOCOL = FREEZE / "analysis_protocol.json"
MANIFEST = FREEZE / "protocol_manifest.json"
BINDING = FREEZE / "semantic_baseline_binding_863.jsonl"

CORE = ROOT / (
    "inputs/core_inject/"
    "final_merged_863/canonical_judge_outcomes.jsonl"
)

SEMANTIC = ROOT / (
    "inputs/judge_analysis/"
    "base_scores.jsonl"
)

OUT = ROOT / (
    "outputs/core_inject_analysis"
)

EXPECTED_BINDING_SHA = (
    "34d52666edf4456cfcfcaa7bc645169e"
    "5346164393072c81b169b92c0dde2557"
)

N = 863
N_CLUSTERS = 101
B = 5000
SEED = 42

CORE_DIM_KEYS = {
    "D1": "D1_contextual_grounding",
    "D2": "D2_mi_adherence",
    "D3": "D3_motivational_attunement",
    "D4": "D4_therapeutic_helpfulness",
    "D5": "D5_naturalness_coherence",
}

SEM_DIM_KEYS = {
    "D1": "D1",
    "D2": "D2",
    "D3": "D3",
    "D4": "D4",
    "D5": "D5",
}


def require(ok, msg):
    if not ok:
        raise RuntimeError(msg)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(
            lambda: f.read(1024 * 1024),
            b"",
        ):
            h.update(block)
    return h.hexdigest()


def canonical_line_bytes(obj) -> bytes:
    return (
        json.dumps(
            obj,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def load_jsonl(path: Path):
    rows = []
    with path.open(
        "r",
        encoding="utf-8",
    ) as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rows.append(json.loads(line))
            except Exception as exc:
                raise RuntimeError(
                    f"JSON parse error {path}:{n}: {exc}"
                )
    return rows


def write_json(path: Path, obj):
    path.write_text(
        json.dumps(
            obj,
            ensure_ascii=True,
            sort_keys=True,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: Path, rows):
    with path.open(
        "w",
        encoding="utf-8",
    ) as f:
        for row in rows:
            f.write(
                json.dumps(
                    row,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            )


def validate_q_short(row):
    for k in ("D1", "D2", "D3", "D4", "D5"):
        require(
            type(row[k]) is int and 1 <= row[k] <= 5,
            f"Invalid semantic {k}",
        )

    expected = (
        row["D1"]
        + row["D2"]
        + row["D3"]
        + row["D4"]
    ) / 4.0

    require(
        float(row["Q"]) == expected,
        "Semantic Q formula drift",
    )


def validate_q_core(row):
    vals = [
        row["D1_contextual_grounding"],
        row["D2_mi_adherence"],
        row["D3_motivational_attunement"],
        row["D4_therapeutic_helpfulness"],
        row["D5_naturalness_coherence"],
    ]

    require(
        all(
            type(x) is int and 1 <= x <= 5
            for x in vals
        ),
        "Invalid CoreInject dimension score",
    )

    expected = sum(vals[:4]) / 4.0

    require(
        float(row["Q"]) == expected,
        "CoreInject Q formula drift",
    )


# ============================================================
# 0. Preflight
# ============================================================

require(
    not OUT.exists(),
    f"Output already exists: {OUT}",
)

for p in (
    PROTOCOL,
    MANIFEST,
    BINDING,
    CORE,
    SEMANTIC,
):
    require(
        p.exists(),
        f"Missing input: {p}",
    )

require(
    sha256_file(BINDING)
    == EXPECTED_BINDING_SHA,
    "Frozen semantic binding SHA drift",
)

manifest = json.loads(
    MANIFEST.read_text(
        encoding="utf-8"
    )
)

require(
    manifest["status"]
    == (
        "CORE_INJECT_B8_PHASE_D6_"
        "STATISTICAL_PROTOCOL_FREEZE_PASS"
    ),
    "D6 core_stage status drift",
)

require(
    manifest["targets"] == N,
    "D6 N drift",
)

require(
    manifest["transcript_clusters"]
    == N_CLUSTERS,
    "D6 cluster count drift",
)

require(
    manifest["bootstrap_replicates"]
    == B,
    "Bootstrap B drift",
)

require(
    manifest["bootstrap_seed"]
    == SEED,
    "Bootstrap seed drift",
)

require(
    manifest["dependence_cluster"]
    == "transcript_id",
    "Cluster rule drift",
)

require(
    manifest["holm_adjustment"]
    is False,
    "Unexpected Holm adjustment",
)

require(
    sha256_file(CORE)
    == manifest[
        "coreinject_source_sha256"
    ],
    "CoreInject source SHA drift",
)

require(
    sha256_file(SEMANTIC)
    == manifest[
        "semantic_source_sha256"
    ],
    "Semantic source SHA drift",
)


# ============================================================
# 1. Load exact frozen pairs
# ============================================================

binding = load_jsonl(BINDING)
core_rows = load_jsonl(CORE)
semantic_rows = load_jsonl(SEMANTIC)

require(
    len(binding) == N,
    "Binding N drift",
)

require(
    len(core_rows) == N,
    "Core N drift",
)

core_by_sid = {
    str(r["sample_id"]): r
    for r in core_rows
}

require(
    len(core_by_sid) == N,
    "Duplicate Core sample ID",
)

paired = []

for bind in binding:

    sid = str(bind["sample_id"])
    transcript_id = str(
        bind["transcript_id"]
    )

    require(
        sid in core_by_sid,
        f"Missing Core row: {sid}",
    )

    core = core_by_sid[sid]

    require(
        str(core["transcript_id"])
        == transcript_id,
        f"Core transcript drift: {sid}",
    )

    source_index = int(
        bind[
            "semantic_source_row_index"
        ]
    )

    require(
        0 <= source_index
        < len(semantic_rows),
        f"Semantic source index invalid: {sid}",
    )

    semantic = semantic_rows[
        source_index
    ]

    require(
        str(semantic["sample_id"])
        == sid,
        f"Semantic sample identity drift: {sid}",
    )

    require(
        str(semantic["transcript_id"])
        == transcript_id,
        f"Semantic transcript drift: {sid}",
    )

    require(
        semantic["condition"]
        == "Semantic-B8",
        f"Semantic condition drift: {sid}",
    )

    require(
        semantic["internal_condition_id"]
        == "semantic_b8",
        f"Semantic internal condition drift: {sid}",
    )

    require(
        semantic["judge_item_id"]
        == bind[
            "semantic_judge_item_id"
        ],
        f"Semantic Judge identity drift: {sid}",
    )

    require(
        hashlib.sha256(
            canonical_line_bytes(
                semantic
            )
        ).hexdigest()
        == bind[
            "semantic_source_row_sha256"
        ],
        f"Semantic source row SHA drift: {sid}",
    )

    validate_q_short(
        semantic
    )

    validate_q_core(
        core
    )

    row = {
        "sample_id":
            sid,

        "transcript_id":
            transcript_id,

        "Q_semantic":
            float(
                semantic["Q"]
            ),

        "Q_coreinject":
            float(
                core["Q"]
            ),

        "delta_Q":
            float(
                core["Q"]
                - semantic["Q"]
            ),

        "critical_violation_semantic":
            bool(
                semantic[
                    "critical_violation"
                ]
            ),

        "critical_violation_coreinject":
            bool(
                core[
                    "critical_violation"
                ]
            ),
    }

    for d in (
        "D1",
        "D2",
        "D3",
        "D4",
        "D5",
    ):

        sem_value = int(
            semantic[
                SEM_DIM_KEYS[d]
            ]
        )

        core_value = int(
            core[
                CORE_DIM_KEYS[d]
            ]
        )

        row[
            f"{d}_semantic"
        ] = sem_value

        row[
            f"{d}_coreinject"
        ] = core_value

        row[
            f"delta_{d}"
        ] = (
            core_value
            - sem_value
        )

    paired.append(row)


require(
    len(paired) == N,
    "Paired N !=863",
)

require(
    len({
        r["sample_id"]
        for r in paired
    }) == N,
    "Duplicate paired target",
)

clusters_set = {
    r["transcript_id"]
    for r in paired
}

require(
    len(clusters_set)
    == N_CLUSTERS,
    "Paired cluster N !=101",
)

# Match the inherited implementation convention:
# transcript IDs are sorted numerically.
try:
    clusters = sorted(
        clusters_set,
        key=lambda x: int(x),
    )
except Exception as exc:
    raise RuntimeError(
        "Transcript IDs are not numerically "
        f"sortable: {exc}"
    )


# ============================================================
# 2. Point estimates — target weighted
# ============================================================

q_sem = np.asarray(
    [
        r["Q_semantic"]
        for r in paired
    ],
    dtype=np.float64,
)

q_core = np.asarray(
    [
        r["Q_coreinject"]
        for r in paired
    ],
    dtype=np.float64,
)

delta_q = (
    q_core - q_sem
)

mean_sem = float(
    q_sem.mean()
)

mean_core = float(
    q_core.mean()
)

mean_delta = float(
    delta_q.mean()
)

sd_delta = float(
    delta_q.std(
        ddof=1
    )
)

dz = (
    float(
        mean_delta
        / sd_delta
    )
    if sd_delta > 0
    else None
)


# ============================================================
# 3. Cluster index
# ============================================================

cluster_to_indices = defaultdict(
    list
)

for i, row in enumerate(
    paired
):
    cluster_to_indices[
        row["transcript_id"]
    ].append(i)


require(
    set(cluster_to_indices)
    == set(clusters),
    "Cluster indexing drift",
)


# ============================================================
# 4. Frozen paired transcript-cluster bootstrap
#
# Each replicate:
# - sample 101 transcript IDs with replacement
# - include ALL paired target rows from each sampled
#   transcript, including duplicate cluster multiplicity
# - target rows remain equally weighted inside replicate
# ============================================================

rng = np.random.default_rng(
    SEED
)

boot_q = np.empty(
    B,
    dtype=np.float64,
)

boot_dims = {
    d: np.empty(
        B,
        dtype=np.float64,
    )
    for d in (
        "D1",
        "D2",
        "D3",
        "D4",
        "D5",
    )
}

dim_delta_arrays = {
    d: np.asarray(
        [
            r[f"delta_{d}"]
            for r in paired
        ],
        dtype=np.float64,
    )
    for d in (
        "D1",
        "D2",
        "D3",
        "D4",
        "D5",
    )
}

cluster_array = np.asarray(
    clusters,
    dtype=object,
)

for b in range(B):

    sampled_clusters = rng.choice(
        cluster_array,
        size=N_CLUSTERS,
        replace=True,
    )

    expanded_indices = []

    for cid in sampled_clusters:

        expanded_indices.extend(
            cluster_to_indices[
                str(cid)
            ]
        )

    idx = np.asarray(
        expanded_indices,
        dtype=np.int64,
    )

    require(
        len(idx) > 0,
        "Empty bootstrap replicate",
    )

    boot_q[b] = float(
        delta_q[idx].mean()
    )

    for d in boot_dims:

        boot_dims[d][b] = float(
            dim_delta_arrays[d][
                idx
            ].mean()
        )


# ============================================================
# 5. Primary inference
# ============================================================

ci_low = float(
    np.percentile(
        boot_q,
        2.5,
    )
)

ci_high = float(
    np.percentile(
        boot_q,
        97.5,
    )
)

null_direction_count = int(
    np.sum(
        boot_q <= 0.0
    )
)

p_one_sided = float(
    (
        null_direction_count
        + 1
    )
    / (
        B + 1
    )
)


# ============================================================
# 6. Secondary descriptive dimensions
# ============================================================

dimension_results = []

for d in (
    "D1",
    "D2",
    "D3",
    "D4",
    "D5",
):

    sem = np.asarray(
        [
            r[f"{d}_semantic"]
            for r in paired
        ],
        dtype=np.float64,
    )

    core = np.asarray(
        [
            r[f"{d}_coreinject"]
            for r in paired
        ],
        dtype=np.float64,
    )

    delta = (
        core - sem
    )

    dimension_results.append(
        {
            "dimension":
                d,

            "semantic_mean":
                float(
                    sem.mean()
                ),

            "coreinject_mean":
                float(
                    core.mean()
                ),

            "paired_mean_difference":
                float(
                    delta.mean()
                ),

            "ci95_low":
                float(
                    np.percentile(
                        boot_dims[d],
                        2.5,
                    )
                ),

            "ci95_high":
                float(
                    np.percentile(
                        boot_dims[d],
                        97.5,
                    )
                ),

            "p_value":
                None,

            "inferential_role":
                "secondary_descriptive",
        }
    )


# ============================================================
# 7. Critical violation descriptive audit
# ============================================================

sem_cv_n = sum(
    r[
        "critical_violation_semantic"
    ]
    for r in paired
)

core_cv_n = sum(
    r[
        "critical_violation_coreinject"
    ]
    for r in paired
)

critical_violation = {
    "Semantic-B8": {
        "count":
            int(sem_cv_n),

        "proportion":
            float(
                sem_cv_n / N
            ),
    },

    "CoreInject-B8": {
        "count":
            int(core_cv_n),

        "proportion":
            float(
                core_cv_n / N
            ),
    },

    "role":
        (
            "secondary descriptive only; "
            "not used for exclusion"
        ),
}


# ============================================================
# 8. Output
# ============================================================

OUT.mkdir(
    parents=True
)

PAIRED_OUT = (
    OUT
    / "paired_target_results.jsonl"
)

BOOT_OUT = (
    OUT
    / "bootstrap_replicates.jsonl"
)

PRIMARY_OUT = (
    OUT
    / "primary_result.json"
)

DIM_OUT = (
    OUT
    / "secondary_dimension_results.csv"
)

CV_OUT = (
    OUT
    / "critical_violation_descriptives.json"
)

write_jsonl(
    PAIRED_OUT,
    paired,
)

bootstrap_rows = []

for b in range(B):

    row = {
        "replicate":
            b,

        "delta_Q":
            float(
                boot_q[b]
            ),
    }

    for d in (
        "D1",
        "D2",
        "D3",
        "D4",
        "D5",
    ):
        row[
            f"delta_{d}"
        ] = float(
            boot_dims[d][b]
        )

    bootstrap_rows.append(
        row
    )


write_jsonl(
    BOOT_OUT,
    bootstrap_rows,
)

primary = {
    "status":
        (
            "CORE_INJECT_B8_PHASE_D7_"
            "STATISTICAL_ANALYSIS_PASS"
        ),

    "analysis_role":
        "post-freeze supplementary",

    "intervention":
        "CoreInject-B8",

    "reference":
        "Semantic-B8",

    "cohort":
        "semantic_missed",

    "targets":
        N,

    "transcript_clusters":
        N_CLUSTERS,

    "semantic_mean_Q":
        mean_sem,

    "coreinject_mean_Q":
        mean_core,

    "paired_mean_delta_Q":
        mean_delta,

    "paired_sd_delta_Q":
        sd_delta,

    "paired_standardized_effect_dz":
        dz,

    "ci95_low":
        ci_low,

    "ci95_high":
        ci_high,

    "hypothesis":
        (
            "H0 DeltaQ<=0 vs "
            "H1 DeltaQ>0"
        ),

    "bootstrap_replicates":
        B,

    "bootstrap_seed":
        SEED,

    "bootstrap_cluster":
        "transcript_id",

    "bootstrap_weighting":
        (
            "target-level equal weighting; "
            "cluster sampling handles dependence"
        ),

    "null_direction_replicates":
        null_direction_count,

    "p_one_sided_plus_one":
        p_one_sided,

    "holm_adjusted":
        False,

    "holm_family":
        None,

    "interpretation_boundary":
        (
            "Full-core restoration under a "
            "fixed B=8 budget; not an isolated "
            "causal effect of one unit or of "
            "coverage as an abstract variable."
        ),
}

write_json(
    PRIMARY_OUT,
    primary,
)

with DIM_OUT.open(
    "w",
    encoding="utf-8",
    newline="",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=[
            "dimension",
            "semantic_mean",
            "coreinject_mean",
            "paired_mean_difference",
            "ci95_low",
            "ci95_high",
            "p_value",
            "inferential_role",
        ],
    )

    writer.writeheader()

    writer.writerows(
        dimension_results
    )


write_json(
    CV_OUT,
    critical_violation,
)


integrity = {
    "targets":
        N,

    "transcript_clusters":
        N_CLUSTERS,

    "pairing_complete":
        True,

    "duplicate_sample_ids":
        0,

    "semantic_binding_sha256":
        sha256_file(
            BINDING
        ),

    "semantic_source_sha256":
        sha256_file(
            SEMANTIC
        ),

    "coreinject_source_sha256":
        sha256_file(
            CORE
        ),

    "bootstrap_replicates":
        B,

    "bootstrap_seed":
        SEED,

    "undefined_bootstrap_replicates":
        0,

    "holm_adjustment":
        False,

    "dimension_specific_p_values":
        False,

    "critical_violation_used_for_exclusion":
        False,

    "api_calls":
        0,

    "judge_calls":
        0,
}

write_json(
    OUT / "analysis_integrity.json",
    integrity,
)


artifact_hashes = {
    p.name:
        sha256_file(p)
    for p in (
        PAIRED_OUT,
        BOOT_OUT,
        PRIMARY_OUT,
        DIM_OUT,
        CV_OUT,
        OUT / "analysis_integrity.json",
    )
}

write_json(
    OUT / "protocol_manifest.json",
    {
        "status":
            (
                "CORE_INJECT_B8_PHASE_D7_"
                "STATISTICAL_ANALYSIS_PASS"
            ),

        "targets":
            N,

        "transcript_clusters":
            N_CLUSTERS,

        "primary_contrast":
            (
                "CoreInject-B8 minus "
                "Semantic-B8"
            ),

        "bootstrap_replicates":
            B,

        "bootstrap_seed":
            SEED,

        "holm_adjustment":
            False,

        "artifact_hashes":
            artifact_hashes,

        "api_calls":
            0,

        "judge_calls":
            0,
    },
)


# ============================================================
# 9. Print only formal aggregate results
# ============================================================

print()
print(
    "CORE_INJECT_B8_PHASE_D7_"
    "STATISTICAL_ANALYSIS"
)
print()

print("targets=863")
print("transcript_clusters=101")

print(
    "semantic_mean_Q="
    f"{mean_sem:.6f}"
)

print(
    "coreinject_mean_Q="
    f"{mean_core:.6f}"
)

print(
    "paired_mean_delta_Q="
    f"{mean_delta:.6f}"
)

print(
    "ci95=["
    f"{ci_low:.6f},"
    f"{ci_high:.6f}"
    "]"
)

print(
    "paired_standardized_effect_dz="
    + (
        f"{dz:.6f}"
        if dz is not None
        else "undefined"
    )
)

print(
    "null_direction_replicates="
    f"{null_direction_count}/5000"
)

print(
    "p_one_sided_plus_one="
    f"{p_one_sided:.6f}"
)

print(
    "holm_adjustment=False"
)

print()
print(
    "SECONDARY_DIMENSIONS"
)

for row in dimension_results:

    print(
        row["dimension"],
        "semantic_mean="
        f"{row['semantic_mean']:.6f}",
        "coreinject_mean="
        f"{row['coreinject_mean']:.6f}",
        "delta="
        f"{row['paired_mean_difference']:.6f}",
        "ci95=["
        f"{row['ci95_low']:.6f},"
        f"{row['ci95_high']:.6f}]",
    )

print()
print(
    "critical_violation_semantic="
    f"{sem_cv_n}/{N}"
)

print(
    "critical_violation_coreinject="
    f"{core_cv_n}/{N}"
)

print()
print(
    "api_calls=0"
)
print(
    "judge_calls=0"
)
print(
    f"output_dir={OUT}"
)

print(
    "STATUS="
    "CORE_INJECT_B8_PHASE_D7_"
    "STATISTICAL_ANALYSIS_PASS"
)
