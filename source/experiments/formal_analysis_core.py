#!/usr/bin/env python3
"""Execute the already frozen RQ1-RQ4 analysis only on explicit --run.

Reuse the hash-pinned gate_stage prerequisite checks, and Sources/strict JSON/hash
utilities from analysis_input.py and
judge_closeout.py. Never call their entry points.
New calculations implement evaluation/analysis_decisions.json.
No network, canonical access, predictor reconstruction, or partial RQ output.
"""
import argparse
from collections import Counter
import csv
import hashlib
import importlib
import io
import json
import math
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from repro_paths import PROJECT_ROOT as ROOT, PYTHON
SELF = ROOT / 'experiments/formal_analysis_core.py'
OUT = ROOT / 'outputs/formal_analysis_core'
INPUT = ROOT / 'inputs/judge_analysis'
F = ROOT / 'protocols'
PRED = ROOT / 'inputs/construct_predictors'
COST = ROOT / 'inputs/cohort'
WORK = ROOT / 'inputs/judge_worklist'
EVAL = F / 'evaluation'
INPUT_SHA = '49bd94437e0a5323d8a647e441120bf2fb6f376c36887aba87a8d9e12e2a6cbc'
PRED_SHA = 'a25b26388b37587665ab1d0c6217229f2a5f33f8effa3a25f41ab0c35610deab'
DECISION_SHA = '919cbec80948e666c66110da33ac79e50cabaf726ab26347b78e2043cdc96398'
MODULES = {
    'formal_analysis_gate': '671125045a95ca8d7cc1bac3f645015056e77e4d1c862f7db6fc27fe6bbb54d2',
    'judge_closeout': 'eac035c0dac6c4ac14288c26b5dd960d0579f2ab623d6fbfe8454b6038f23ad9',
    'analysis_input': '4b8f627d22d01c73dfd125adccb7a379cfdefa78f47462c6cf39177c3dccdbdf'}
B8 = ('Random-B8', 'k8 / Recent-B8', 'Semantic-B8', 'PredictedMI-B8', 'OracleMI-B8')
RQ1 = ('k1', 'k2', 'k4', 'k8 / Recent-B8', 'k16', 'Full')
ALL = RQ1 + ('Random-B8', 'Semantic-B8', 'PredictedMI-B8', 'OracleMI-B8')
TERMINAL = 'd4d357fc531cf9c9b2af0e9a83d3967e701ac53096d3872ee76dd2cc05ba9e37'
TERMINAL_SAMPLE = 'annomi_t78_target_32'
FILES = {'analysis_summary.json', 'base_descriptive_by_condition.csv', 'rq1_context_sufficiency.csv',
         'rq1_secondary_dimensions.csv', 'rq2_policy_comparisons.csv', 'rq2_construct_model.json',
         'rq2_holm_family.csv', 'rq3_predicted_vs_full.csv', 'rq4_mechanism_interactions.csv',
         'analysis_integrity.json', 'source_artifact_hashes.json', 'protocol_manifest.json', 'checksums.sha256'}
STATUS = 'FORMAL_ANALYSIS_CORE_COMPLETE'
FLAGS = {'quality_scores_read': False, 'descriptive_statistics_computed': False,
         'inferential_statistics_computed': False, 'research_effect_direction_inspected': False,
         'output_created': False, 'API_calls': 0, 'Judge_calls': 0, 'generation_calls': 0,
         'S_or_M_reconstruction_performed': False, 'judge_canonical_payloads_read': False}


class Blocked(RuntimeError):
    pass


def require(ok, reason):
    if not ok:
        raise Blocked(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def guard(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn')) or event in (
            'os.system', 'os.fork', 'os.kill', 'os.killpg', 'os.remove', 'os.rename', 'os.rmdir',
            'os.link', 'os.symlink', 'os.chmod', 'os.chown', 'os.utime', 'os.truncate'):
        raise Blocked('NETWORK_PROCESS_OR_EXISTING_FILE_MUTATION_FORBIDDEN')
    if event == 'os.mkdir':
        require(Path(args[0]).absolute() == OUT, 'UNAUTHORIZED_DIRECTORY_WRITE')
    if event != 'open' or not isinstance(args[0], (str, bytes, os.PathLike)):
        return
    p = Path(os.fsdecode(args[0])).absolute()
    if p.is_relative_to(ROOT):
        rel = p.relative_to(ROOT).as_posix()
        require(not rel.startswith(('inputs/judge_runtime/', 'inputs/generation_outputs')),
                'CANONICAL_OR_GENERATION_RESULT_ACCESS_FORBIDDEN')
        require(p.name not in ('blind_worklist.jsonl', 'human_validation_subset.jsonl'), 'RESPONSE_TEXT_ACCESS_FORBIDDEN')
    if args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        require(p.parent == OUT and p.name in FILES and args[2] & os.O_EXCL and args[2] & os.O_CREAT,
                'ONLY_EXCLUSIVE_NEW_RESULT_FILES_ALLOWED')


def load_modules():
    for name, sha in MODULES.items():
        p = ROOT / 'experiments' / (name + '.py')
        require(p.resolve() == p and digest(p.read_bytes()) == sha, 'PINNED_IMPLEMENTATION_MISMATCH')
    modules = {name: importlib.import_module(name) for name in MODULES}
    for name, module in modules.items():
        require(Path(module.__file__).absolute() == ROOT / 'experiments' / (name + '.py'), 'WRONG_MODULE_IMPORT')
    return modules


def unique(rows, fields):
    result = {}
    for row in rows:
        key = tuple(row[k] for k in fields)
        require(key not in result, 'DUPLICATE_FROZEN_IDENTITY')
        result[key] = row
    return result


def prepare(modules):
    gate_stage = modules['formal_analysis_gate']
    # An in-memory wrapper only. The immutable gate_stage source and every rule remain unchanged.
    gate_stage.OUT = OUT
    prior = gate_stage.check_sources()
    require(prior['reason'] == 'MISSING_FROZEN_CONSTRUCT_PREDICTOR_ARTIFACT' and
            prior['quality_scores_read'] is False and prior['output_created'] is False and
            all(prior['protocol_recovery'][k] == 'PASS' for k in
                ('RQ1', 'RQ2_policy', 'RQ2_construct_protocol', 'RQ3', 'RQ4')), 'GATE_PROTOCOL_RECOVERY_FAILED')
    h = modules['judge_closeout']
    a = modules['analysis_input']
    s = a.Sources(h)
    s.track(SELF)
    for name, pin in MODULES.items():
        s.track(ROOT / 'experiments' / (name + '.py'), pin)
    inputs = s.bundle(INPUT, INPUT_SHA)
    parents = {name: s.bundle(F / name, pin) for name, pin in gate_stage.PINS.items()}
    s.track(EVAL / 'analysis_decisions.json', DECISION_SHA)
    decisions = s.read(EVAL / 'analysis_decisions.json')
    # Exact decision-file hash binds all tails, ties, interpolation and undefined-replicate rules.
    tests = decisions['bootstrap_test_details']
    require(tests['replicates'] == 5000 and tests['seed'] == 42 and decisions['delta_Q'] == 0.25,
            'MISSING_FROZEN_BOOTSTRAP_DETAILS')
    cost = parents['cohort']
    scope = s.read(COST / 'analysis_scope.json')
    for key in ('RQ1', 'RQ2_policy_utility', 'RQ2_construct_level_incrementality', 'RQ3'):
        require(scope[key]['cohort'] == 'Base-1000 only', 'COHORT_DEFINITION_DRIFT')
    base_records = list(s.lines(COST / 'base_1000_targets.jsonl'))
    order = [row['sample_id'] for row in base_records]
    require(len(order) == len(set(order)) == 1000 and
            [row['selection_rank'] for row in base_records] == list(range(1, 1001)), 'BASE_TARGET_ORDER_DRIFT')
    authorized = unique(s.lines(COST / 'final_authorized_items.jsonl'), ('sample_id', 'condition'))
    by_jid = {row['judge_item_id']: row for row in authorized.values()}
    require(len(authorized) == len(by_jid) == 10366, 'AUTHORIZED_UNION_DRIFT')
    sets = {}
    for key, name in [('base', 'base_1000_items.jsonl'), ('recent', 'rq4_recent_enrichment_items.jsonl'),
                      ('semantic', 'rq4_semantic_enrichment_items.jsonl'), ('human', 'human_120_items.jsonl')]:
        part = unique(s.lines(COST / name), ('judge_item_id',))
        sets[key] = {jid[0] for jid in part}
        require(all(jid[0] in by_jid and row == by_jid[jid[0]] for jid, row in part.items()), 'COHORT_COMPONENT_DRIFT')
    require(set.union(*sets.values()) == set(by_jid) and len(sets['base']) == 10000 and len(sets['human']) == 120,
            'COHORT_COMPONENT_UNION_MISMATCH')
    require({(sample, condition) for sample in order for condition in ALL} ==
            {key for key, row in authorized.items() if row['judge_item_id'] in sets['base']}, 'BASE_TEN_CONDITION_COVERAGE')
    for row in authorized.values():
        for key, field in [('base', 'membership_base_1000'), ('recent', 'membership_rq4_recent'),
                           ('semantic', 'membership_rq4_semantic'), ('human', 'membership_human_120')]:
            require(row[field] is (row['judge_item_id'] in sets[key]), 'MEMBERSHIP_FLAG_MISMATCH')
    work_pin = inputs['judge_worklist_manifest_sha256']
    s.track(WORK / 'protocol_manifest.json', work_pin)
    work = s.read(WORK / 'protocol_manifest.json')
    id_path = WORK / 'identities.jsonl'
    s.track(id_path, work['artifact_hashes'][id_path.name])
    identities = {}; target_transcript = {}; primary_pairs = set(); all_jids = set()
    for index, row in enumerate(s.lines(id_path)):
        key = (row['sample_id'], row['condition']); jid = row['judge_item_id']; tid = row['transcript_id']
        require(key not in primary_pairs and jid not in all_jids and type(tid) is str and tid.isdigit(), 'PRIMARY_IDENTITY_NOT_UNIQUE')
        primary_pairs.add(key); all_jids.add(jid)
        require(row['sample_id'] not in target_transcript or target_transcript[row['sample_id']] == tid, 'TRANSCRIPT_JOIN_DRIFT')
        target_transcript[row['sample_id']] = tid
        if key in authorized:
            frozen = authorized[key]
            require(jid == frozen['judge_item_id'] and row['internal_condition_id'] == frozen['internal_condition_id'] and
                    index == frozen['worklist_index'] and frozen['shard_id'] == index % 8, 'AUTHORIZED_IDENTITY_JOIN_DRIFT')
            identities[key] = {k: row[k] for k in ('sample_id', 'condition', 'judge_item_id', 'internal_condition_id', 'transcript_id')}
            identities[key].update(original_worklist_index=index, shard_id=index % 8)
    require(len(primary_pairs) == 38240 and len(target_transcript) == 3824 and set(identities) == set(authorized), 'PRIMARY_POPULATION_DRIFT')
    require(primary_pairs == {(sample, c) for sample in target_transcript for c in ALL}, 'PRIMARY_CONDITIONS_DRIFT')
    clusters = sorted(set(target_transcript.values()), key=int)
    require(len(clusters) == len({int(t) for t in clusters}) == 118, 'PRIMARY_CLUSTER_POPULATION_DRIFT')
    groups = {}; rq4 = {}; group_manifests = {}
    expected_groups = {'recent': {'recent_missed': 3181, 'recent_covered': 131, 'no_oracle_core_selected': 512},
                       'semantic': {'semantic_missed': 3230, 'semantic_covered': 82, 'no_oracle_core_selected': 512}}
    expected_pairs = {'recent': (971, 840, 131), 'semantic': (945, 863, 82)}
    audit = s.read(INPUT / 'integrity_audit.json')
    for mode, other in [('recent', 'k8 / Recent-B8'), ('semantic', 'Semantic-B8')]:
        path = h.safe(ROOT / decisions['mechanism'][mode + '_group_artifact'])
        group_manifests[mode] = s.bundle(path.parent, cost['parent_manifest_sha256'][path.parent.relative_to(ROOT).as_posix()])
        g = {key[0]: row for key, row in unique(s.lines(path), ('sample_id',)).items()}
        require(set(g) == set(target_transcript) and dict(Counter(x['mechanism_group'] for x in g.values())) == expected_groups[mode] and
                all(x['transcript_id'] == target_transcript[sample] for sample, x in g.items()), 'FROZEN_MECHANISM_GROUP_DRIFT')
        covered = {sample for sample, row in g.items() if row['mechanism_group'] == mode + '_covered'}
        expected_enrichment = {authorized[(sample, c)]['judge_item_id'] for sample in covered for c in ('PredictedMI-B8', other)}
        require(sets[mode] == expected_enrichment, 'RQ4_ENRICHMENT_DRIFT')
        population = set(order) | covered
        selected = [sample for sample in sorted(population) if g[sample]['mechanism_group'] != 'no_oracle_core_selected']
        n, nm, nc = expected_pairs[mode]
        require(len(selected) == n and len(population) - n == 118 and
                Counter(g[sample]['mechanism_group'] for sample in selected) == {mode + '_missed': nm, mode + '_covered': nc}, 'RQ4_PAIR_POPULATION_DRIFT')
        require(all((sample, c) in identities for sample in selected for c in ('PredictedMI-B8', other)), 'RQ4_IDENTITY_COVERAGE')
        frozen_audit = audit['rq4_required_pair_coverage'][mode]
        require(frozen_audit['complete_pairs'] == n and frozen_audit['groups'] == {mode + '_missed': nm, mode + '_covered': nc} and
                frozen_audit['no_oracle_core_selected_targets_not_in_primary_interaction'] == 118, 'RQ4_INPUT_AUDIT_DRIFT')
        groups[mode] = g; rq4[mode] = {'samples': selected, 'other': other, 'support': frozen_audit}
    old = s.read(F / 'analysis_scope/analysis_protocol.json')
    require(old['quality_cost'] == decisions['token_metric_inherited_unchanged'], 'TOKEN_PROTOCOL_DRIFT')
    require(old['bootstrap_replicates'] == 5000 and old['bootstrap_seed'] == 42 and old['dependence_cluster'] == 'transcript_id',
            'INHERITED_STATISTICAL_RULE_DRIFT')
    s.read(F / 'analysis_scope/research_questions.json')
    s.read(F / 'mechanism_groups/mechanism_definition.json')
    predictor_manifest = s.bundle(PRED, PRED_SHA)
    require(predictor_manifest['status'] == 'RQ2_CONSTRUCT_PREDICTOR_TABLE_FROZEN' and
            predictor_manifest['target_count'] == 1000 and predictor_manifest['predictor_row_count'] == 5000 and
            predictor_manifest['conditions'] == list(B8) and predictor_manifest['condition_counts'] == {c: 1000 for c in B8} and
            predictor_manifest['selected_history_count'] == 7 and predictor_manifest['join_keys'] == ['sample_id', 'condition'] and
            predictor_manifest['construct_protocol_manifest_sha256'] == gate_stage.PINS['construct_definition'], 'PREDICTOR_MANIFEST_DRIFT')
    require(all(predictor_manifest[k] is False for k in ('quality_scores_read', 'judge_canonical_payloads_read',
                'outcome_based_filtering', 'research_effect_direction_inspected')), 'PREDICTOR_OUTCOME_INDEPENDENCE_FAILED')
    predictor_path = h.safe(PRED / predictor_manifest['predictor_artifact'])
    require(predictor_path.parent == PRED and predictor_path.name in predictor_manifest['artifact_hashes'], 'PREDICTOR_SOURCE_NOT_FROZEN')
    predictor_list = list(s.lines(predictor_path)); predictors = unique(predictor_list, ('sample_id', 'condition'))
    require(list(predictors) == [(sample, c) for sample in order for c in B8] and len(predictors) == 5000, 'PREDICTOR_COHORT_OR_ORDER_DRIFT')
    for key, row in predictors.items():
        require(all(row[k] == identities[key][k] for k in ('sample_id', 'condition', 'transcript_id', 'judge_item_id',
                    'internal_condition_id', 'original_worklist_index', 'shard_id')), 'PREDICTOR_IDENTITY_JOIN_DRIFT')
        require(row['selected_history_count'] == 7 and len(set(row['selected_history_unit_ids'])) == 7 and
                row['current_client_canonical_unit_id'] not in row['selected_history_unit_ids'] and
                all(type(row[k]) in (float, int) and math.isfinite(row[k]) for k in ('S_is', 'M_is')) and
                type(row['mi_process_positive_count']) is int and 0 <= row['mi_process_positive_count'] <= 7 and
                row['M_is'] == row['mi_process_positive_count'] / 7, 'INVALID_FROZEN_PREDICTOR_ROW')
    missing = s.read(INPUT / 'terminal_missing.json')
    require(missing['judge_item_id'] == TERMINAL and missing['sample_id'] == TERMINAL_SAMPLE and missing['condition'] == 'k16' and
            missing['quality_based_missingness'] is False and missing['canonical_exists'] is False, 'TERMINAL_MISSINGNESS_DRIFT')
    token = {'status': 'NOT_COMPUTED_SOURCE_UNAVAILABLE', 'frozen_definition': old['quality_cost'],
             'reason': 'Referenced scope freeze records token_cost_values_computed=false; no hash-bound paired token-value artifact is registered in these analysis inputs.',
             'Judge_usage_used': False, 'token_reconstruction_performed': False}
    require(group_manifests['recent']['token_cost_values_computed'] is False and
            old['quality_cost']['calculation_status'] == 'DEFERRED_PROTOCOL_ONLY', 'UNRECOGNIZED_TOKEN_SOURCE_STATE')
    s.stable()
    return {'s': s, 'h': h, 'decisions': decisions, 'prior': prior, 'inputs': inputs, 'order': order,
            'authorized': authorized, 'identities': identities, 'sets': sets, 'clusters': clusters,
            'transcripts': target_transcript, 'groups': groups, 'rq4': rq4, 'predictors': predictors,
            'predictor_path': predictor_path, 'predictor_manifest': predictor_manifest, 'token': token}


def load_outcomes(state):
    s = state['s']; FLAGS['quality_scores_read'] = True
    authorized = unique(s.lines(INPUT / 'scores.jsonl'), ('sample_id', 'condition'))
    expected = set(state['authorized']) - {(TERMINAL_SAMPLE, 'k16')}
    require(set(authorized) == expected and len(authorized) == 10365, 'AUTHORIZED_OUTCOME_COVERAGE_DRIFT')
    for key, row in authorized.items():
        require(all(row[k] == v for k, v in state['identities'][key].items()), 'OUTCOME_IDENTITY_MISMATCH')
        require(all(type(row[f'D{i}']) is int and 1 <= row[f'D{i}'] <= 5 for i in range(1, 6)) and
                type(row['critical_violation']) is bool and type(row['Q']) in (float, int) and
                row['Q'] == sum(row[f'D{i}'] for i in range(1, 5)) / 4, 'OUTCOME_SCHEMA_OR_Q_MISMATCH')
        for key2, field in [('base', 'base_1000_member'), ('recent', 'rq4_recent_member'), ('semantic', 'rq4_semantic_member'), ('human', 'human_120_member')]:
            require(row[field] is (row['judge_item_id'] in state['sets'][key2]), 'OUTCOME_MEMBERSHIP_MISMATCH')
    base = unique(s.lines(INPUT / 'base_scores.jsonl'), ('sample_id', 'condition'))
    rq1 = unique(s.lines(INPUT / 'rq1_scores.jsonl'), ('sample_id', 'condition'))
    rq1_order = [sample for sample in state['order'] if sample != TERMINAL_SAMPLE]
    require(list(base) == [(sample, c) for sample in state['order'] for c in ALL if (sample, c) != (TERMINAL_SAMPLE, 'k16')] and
            len(base) == 9999 and all(row == authorized[key] for key, row in base.items()), 'BASE_OUTCOME_SUBSET_DRIFT')
    require(list(rq1) == [(sample, c) for sample in rq1_order for c in RQ1] and len(rq1) == 5994 and
            all(row == base[key] for key, row in rq1.items()), 'RQ1_COMPLETE_CASE_SUBSET_DRIFT')
    matched = {key: base[key] for key in state['predictors']}
    require(len(matched) == 5000 and len({key[0] for key in matched}) == 1000 and
            Counter(key[1] for key in matched) == {c: 1000 for c in B8}, 'CONSTRUCT_OUTCOME_JOIN_NOT_5000')
    for key, row in matched.items():
        require(all(row[k] == state['predictors'][key][k] for k in ('transcript_id', 'internal_condition_id', 'judge_item_id')),
                'CONSTRUCT_OUTCOME_IDENTITY_MISMATCH')
    for mode, spec in state['rq4'].items():
        require(all((sample, c) in authorized for sample in spec['samples'] for c in ('PredictedMI-B8', spec['other'])), 'RQ4_OUTCOME_PAIR_MISSING')
    state.update(base=base, rq1_rows=rq1, rq1_order=rq1_order, outcomes=authorized)
    s.stable()


def mean(values):
    require(bool(values), 'EMPTY_DESCRIPTIVE_POPULATION')
    return math.fsum(values) / len(values)


def sd(values):
    if len(values) < 2:
        return None
    avg = mean(values)
    return math.sqrt(math.fsum((x - avg) ** 2 for x in values) / (len(values) - 1))


class Engine:
    def __init__(self, np, state):
        self.np = np; self.state = state; self.clusters = state['clusters']; self.G = len(self.clusters)
        self.cluster_index = {tid: i for i, tid in enumerate(self.clusters)}
        rng = np.random.Generator(np.random.PCG64(42))
        self.counts = np.empty((5000, self.G), dtype=np.int64)
        raw_hash = hashlib.sha256()
        for b in range(5000):
            draw = rng.integers(0, self.G, size=self.G)
            raw_hash.update(draw.astype('<i8', copy=False).tobytes())
            self.counts[b] = np.bincount(draw, minlength=self.G)
        self.draw_hash = raw_hash.hexdigest()

    def indices(self, samples):
        return self.np.array([self.cluster_index[self.state['transcripts'][sample]] for sample in samples], dtype=int)

    def distribution(self, values, samples):
        np = self.np; idx = self.indices(samples)
        n = np.bincount(idx, minlength=self.G)
        totals = np.bincount(idx, weights=np.asarray(values, dtype=float), minlength=self.G)
        denominator = self.counts @ n
        distribution = np.full(5000, np.nan)
        np.divide(self.counts @ totals, denominator, out=distribution, where=denominator > 0)
        return distribution

    def inference(self, estimate, distribution, alternative):
        np = self.np; finite = np.isfinite(distribution); n = int(finite.sum())
        point_valid = estimate is not None and math.isfinite(estimate)
        valid = point_valid and n == 5000
        interval = np.quantile(distribution[finite], [0.025, 0.975], method='linear').tolist() if n else [None, None]
        p = None
        if valid:
            error = distribution - estimate
            count = int(np.count_nonzero(error >= estimate + 0.25)) if alternative == 'NI' else int(np.count_nonzero(np.abs(error) >= abs(estimate)))
            p = (1 + count) / 5001
        return {'estimate': estimate if point_valid else None, 'status': 'ESTIMABLE' if valid else 'NON_ESTIMABLE',
                'ci_low': interval[0] if valid else None, 'ci_high': interval[1] if valid else None,
                'valid_replicate_percentile_low': interval[0], 'valid_replicate_percentile_high': interval[1],
                'interval_role': 'formal_effect_interval' if valid else 'descriptive_valid_replicates_only',
                'bootstrap_valid_replicates': n, 'bootstrap_undefined_replicates': 5000 - n,
                'undefined_replicate_ids': (np.flatnonzero(~finite) + 1).tolist(),
                'raw_p': p, 'holm_input_p': p if valid else 1.0, 'multiplicity_placeholder': not valid,
                'alternative': 'theta > -0.25' if alternative == 'NI' else 'theta != 0',
                'CI_definition': 'percentile 95%, linear/type7; separate from NI decision',
                'undefined_reason': None if valid else 'point_or_replicate_empty_support_or_design_rank_deficiency'}

    def pair(self, rows, samples, left, right, alternative='two_sided'):
        lhs = [rows[(sample, left)]['Q'] for sample in samples]; rhs = [rows[(sample, right)]['Q'] for sample in samples]
        diff = [a - b for a, b in zip(lhs, rhs)]; est = mean(diff); spread = sd(diff)
        distribution = self.distribution(diff, samples)
        result = self.inference(est, distribution, alternative)
        result.update(left_condition=left, right_condition=right, N_targets=len(samples),
                      N_transcript_clusters=len(set(self.state['transcripts'][s] for s in samples)),
                      mean_left_Q=mean(lhs), mean_right_Q=mean(rhs), paired_SD=spread,
                      paired_d_z=est / spread if spread else None)
        return result, distribution


def holm(results, ni=False):
    ordered = sorted(range(len(results)), key=lambda i: (results[i]['holm_input_p'], i))
    previous = 0.0
    for rank, i in enumerate(ordered):
        previous = min(1.0, max(previous, (len(results) - rank) * results[i]['holm_input_p']))
        row = results[i]; row['holm_adjusted_p'] = previous; row['holm_family_size'] = len(results)
        row['holm_adjusted_p_is_conservative_placeholder'] = row['multiplicity_placeholder']
        row['reject_null'] = row['status'] == 'ESTIMABLE' and previous <= 0.05
        if ni:
            row['delta_Q'] = 0.25
            row['NI_pass'] = row['reject_null'] and row['estimate'] > -0.25


def fixed_effects(np, x, y, target_weights):
    """FWL for balanced five-condition panels, including cluster multiplicity.

    Project out target effects first, then frequency-weighted condition effects.
    This is the complete frozen two-way FE model, not a reduced covariate model.
    Zero-weight targets correspond only to clusters not drawn by bootstrap.
    """
    active = target_weights > 0
    if not active.any():
        return None, 'empty_bootstrap_target_support'
    x = x[active]; y = y[active]; weights = target_weights[active]
    xw = x - x.mean(axis=1, keepdims=True); yw = y - y.mean(axis=1, keepdims=True)
    xw = xw - np.sum(weights[:, None, None] * xw, axis=0, keepdims=True) / weights.sum()
    yw = yw - np.sum(weights[:, None] * yw, axis=0, keepdims=True) / weights.sum()
    xx = (xw * np.sqrt(weights)[:, None, None]).reshape(-1, 2)
    yy = (yw * np.sqrt(weights)[:, None]).reshape(-1)
    try:
        beta, _, rank, _ = np.linalg.lstsq(xx, yy, rcond=None)
    except np.linalg.LinAlgError:
        return None, 'least_squares_nonconvergence'
    if rank != 2 or not np.isfinite(beta).all():
        return None, 'full_fixed_effects_design_rank_deficient'
    return beta, None


def construct(engine, state):
    np = engine.np; samples = state['order']
    x = np.array([[[state['predictors'][(s, c)][k] for k in ('S_is', 'M_is')] for c in B8] for s in samples], dtype=float)
    y = np.array([[state['base'][(s, c)]['Q'] for c in B8] for s in samples], dtype=float)
    point, reason = fixed_effects(np, x, y, np.ones(len(samples)))
    distribution = np.full((5000, 2), np.nan); failures = Counter(); cluster_ids = engine.indices(samples)
    for b in range(5000):
        beta, why = fixed_effects(np, x, y, engine.counts[b, cluster_ids])
        if why:
            failures[why] += 1
        else:
            distribution[b] = beta
    results = {}
    for i, name in enumerate(('beta_S', 'beta_M')):
        result = engine.inference(None if point is None else float(point[i]), distribution[:, i], 'two_sided')
        result['bootstrap_SD'] = sd(distribution[np.isfinite(distribution[:, i]), i].tolist())
        result['bootstrap_SD_role'] = 'uncertainty_summary' if result['status'] == 'ESTIMABLE' else 'descriptive_valid_replicates_only'
        if name == 'beta_S':
            # Supporting coefficient uncertainty only, not an added confirmatory test.
            for key in ('raw_p', 'holm_input_p', 'multiplicity_placeholder', 'alternative'):
                result.pop(key)
        results[name] = result
    report = {'model': 'U_is = alpha_i + gamma_s + beta_S*S_is + beta_M*M_is + epsilon_is',
              'interpretation': 'conditional association / incremental explanatory dimension; not causal',
              'N_rows': 5000, 'N_targets': 1000, 'N_transcript_clusters': len(set(state['transcripts'][s] for s in samples)),
              'conditions': list(B8), 'condition_counts': {c: 1000 for c in B8}, 'Full_excluded': True,
              'estimator': 'Full two-way fixed-effects least squares via weighted FWL; refit every replicate',
              'numerical_solver': 'numpy.linalg.lstsq rcond=None on residualized two-column design; no regularization',
              'cluster_duplicates': 'Integer transcript multiplicity as target frequency weights; never deduplicated',
              'point_non_estimable_reason': reason, 'replicate_failure_reasons': dict(failures),
              'coefficient_uncertainty': '5000 shared transcript-cluster refits; percentile/type7 CI',
              'coefficients': results, 'S_or_M_reconstruction_performed': False}
    return report


def descriptive(rows, conditions, cohort):
    result = []
    for c in conditions:
        group = [row for (_, condition), row in rows.items() if condition == c]
        q = [row['Q'] for row in group]; violations = sum(row['critical_violation'] for row in group)
        result.append({'cohort': cohort, 'condition': c, 'N': len(group), 'mean_Q': mean(q), 'SD_Q': sd(q),
                       **{f'mean_D{i}': mean([row[f'D{i}'] for row in group]) for i in range(1, 6)},
                       'critical_violation_count': violations, 'critical_violation_rate': violations / len(group),
                       'critical_violation_exclusions': 0})
    return result


def synthetic_checks(np):
    """Run only after user --run, before outcomes; no project or result access."""
    rng = np.random.Generator(np.random.PCG64(13))
    x = rng.normal(size=(6, 5, 2)); weights = np.array([1, 2, 0, 3, 1, 2])
    y = x @ np.array([0.75, -0.4]) + np.arange(6)[:, None] + np.arange(5)[None, :]
    beta, reason = fixed_effects(np, x, y, weights)
    require(reason is None and np.allclose(beta, [0.75, -0.4], atol=1e-10, rtol=1e-10), 'SYNTHETIC_FE_KNOWN_COEFFICIENT_FAILED')
    expanded_x = np.repeat(x, weights, axis=0); expanded_y = np.repeat(y, weights, axis=0); n = len(expanded_x)
    design = np.column_stack([np.repeat(np.eye(n), 5, axis=0), np.tile(np.eye(5)[:, 1:], (n, 1)), expanded_x.reshape(-1, 2)])
    direct = np.linalg.lstsq(design, expanded_y.ravel(), rcond=None)[0][-2:]
    require(np.allclose(beta, direct, atol=1e-10, rtol=1e-10), 'SYNTHETIC_FREQUENCY_WEIGHT_FWL_FAILED')
    zero, why = fixed_effects(np, np.zeros_like(x), y, weights)
    require(zero is None and why == 'full_fixed_effects_design_rank_deficient', 'SYNTHETIC_RANK_POLICY_FAILED')
    rows = [{'holm_input_p': p, 'status': 'ESTIMABLE', 'multiplicity_placeholder': False} for p in (0.01, 0.02, 0.02)]
    holm(rows)
    require([r['holm_adjusted_p'] for r in rows] == [0.03, 0.04, 0.04], 'SYNTHETIC_HOLM_FAILED')
    fake = object.__new__(Engine); fake.np = np
    boundary = fake.inference(-0.25, np.full(5000, -0.25), 'NI')
    require(boundary['raw_p'] == 1.0, 'SYNTHETIC_NI_BOUNDARY_FAILED')
    invalid = fake.inference(1.0, np.full(5000, np.nan), 'two_sided')
    require(invalid['status'] == 'NON_ESTIMABLE' and invalid['raw_p'] is None and invalid['holm_input_p'] == 1.0,
            'SYNTHETIC_UNDEFINED_POLICY_FAILED')


def csv_bytes(rows):
    require(bool(rows), 'EMPTY_RESULT_TABLE')
    stream = io.StringIO(newline=''); fields = sorted(set().union(*(row.keys() for row in rows)))
    writer = csv.DictWriter(stream, fieldnames=fields, lineterminator='\n'); writer.writeheader()
    for row in rows:
        writer.writerow({key: json.dumps(value, sort_keys=True, allow_nan=False) if isinstance(value, (list, dict)) else value for key, value in row.items()})
    return stream.getvalue().encode('utf-8')


def calculate(state, np):
    engine = Engine(np, state); d = state['decisions']; families = d['confirmatory_families']
    rq1 = []
    for k, c, label in zip((1, 2, 4, 8, 16), RQ1[:-1], families['RQ1']['contrasts']):
        row, _ = engine.pair(state['rq1_rows'], state['rq1_order'], c, 'Full', 'NI')
        row.update(context_size=k, contrast=label); rq1.append(row)
    holm(rq1, ni=True)
    qualifiers = [row['context_size'] for row in rq1 if row['NI_pass']]
    rq2 = []
    for left, label in zip(('PredictedMI-B8', 'OracleMI-B8'), families['RQ2']['contrasts'][:2]):
        row, _ = engine.pair(state['base'], state['order'], left, 'Semantic-B8')
        row['contrast'] = label; rq2.append(row)
    model = construct(engine, state); beta_m = model['coefficients']['beta_M']; beta_m['contrast'] = 'beta_M'
    rq2_family = rq2 + [beta_m]; holm(rq2_family)
    rq3, _ = engine.pair(state['base'], state['order'], 'PredictedMI-B8', 'Full', 'NI')
    rq3['contrast'] = families['RQ3']['contrasts'][0]; holm([rq3], ni=True)
    rq3['token_reduction_status'] = state['token']['status']
    rq4 = []
    # The frozen listed order is semantic first, recent second (including Holm ties).
    for mode, label in zip(('semantic', 'recent'), families['RQ4']['contrasts']):
        spec = state['rq4'][mode]; groups = state['groups'][mode]
        missed = [s for s in spec['samples'] if groups[s]['mechanism_group'] == mode + '_missed']
        covered = [s for s in spec['samples'] if groups[s]['mechanism_group'] == mode + '_covered']
        mr, mb = engine.pair(state['outcomes'], missed, 'PredictedMI-B8', spec['other'])
        cr, cb = engine.pair(state['outcomes'], covered, 'PredictedMI-B8', spec['other'])
        row = engine.inference(mr['estimate'] - cr['estimate'], mb - cb, 'two_sided')
        row.update(contrast=label, mode=mode, missed_N=len(missed), covered_N=len(covered),
                   N_targets=len(spec['samples']), missed_transcript_clusters=mr['N_transcript_clusters'],
                   covered_transcript_clusters=cr['N_transcript_clusters'],
                   N_transcript_clusters=len(set(state['transcripts'][s] for s in spec['samples'])),
                   missed_mean_paired_effect=mr['estimate'], covered_mean_paired_effect=cr['estimate'],
                   missed_paired_d_z=mr['paired_d_z'], covered_paired_d_z=cr['paired_d_z'],
                   missed_undefined_replicates=mr['bootstrap_undefined_replicates'],
                   covered_undefined_replicates=cr['bootstrap_undefined_replicates'], no_oracle_excluded=118)
        rq4.append(row)
    holm(rq4)
    FLAGS.update(descriptive_statistics_computed=True, inferential_statistics_computed=True, research_effect_direction_inspected=True)
    tests = rq1 + rq2_family + [rq3] + rq4
    summary = {'RQ1_k_star': min(qualifiers) if qualifiers else None,
               'RQ1_qualification_status': 'FINITE_QUALIFIER' if qualifiers else families['RQ1']['no_qualifier'],
               'monotonicity_assumed': False, 'confirmatory_tests': len(tests),
               'non_estimable_tests': [row['contrast'] for row in tests if row['status'] == 'NON_ESTIMABLE'],
               'non_estimable_policy': d['bootstrap_test_details']['non_estimable_policy'],
               'RQ2_interpretation': model['interpretation'], 'RQ3_token_reduction': state['token'],
               'RQ4_enriched_cohorts_not_simple_random_samples': True,
               'reuse_time_provenance': d['statistical_core']['reuse_time_provenance'],
               'output_means_do_not_select_responses_or_methods': True}
    integrity = {'analysis_input_manifest_sha256': INPUT_SHA, 'construct_predictor_manifest_sha256': PRED_SHA,
                 'RQ1_targets': 999, 'RQ1_rows': 5994, 'RQ1_cluster_unit': 'transcript_id',
                 'RQ1_bootstrap_replicates': 5000, 'RQ1_bootstrap_seed': 42, 'RQ1_holm_family_size': 5, 'RQ1_delta_Q': 0.25,
                 'RQ2_pred_sem_pairs': 1000, 'RQ2_oracle_sem_pairs': 1000, 'RQ2_construct_rows': 5000,
                 'RQ2_construct_targets': 1000, 'RQ2_holm_family_size': 3, 'RQ2_construct_full_excluded': True,
                 'RQ3_pairs': 1000, 'RQ3_delta_Q': 0.25, 'RQ4_recent_pairs': 971, 'RQ4_semantic_pairs': 945,
                 'RQ4_holm_family_size': 2, 'technical_missing_items': 1, 'quality_based_exclusions': 0,
                 'critical_violation_exclusions': 0, 'predictor_join_keys': ['sample_id', 'condition'],
                 'predictor_join_pass': True, 'primary_cluster_count': engine.G, 'primary_cluster_ids': engine.clusters,
                 'shared_bootstrap_draws_sha256': engine.draw_hash, 'draw_hash_encoding': 'replicate-order little-endian int64 indices',
                 'all_estimands_share_same_cluster_draws': True, 'undefined_replicates_redrawn': False,
                 'non_estimable_tests': summary['non_estimable_tests'], 'synthetic_checks_before_outcomes': 'PASS',
                 **FLAGS, 'output_created': True}
    h = state['h']
    artifacts = {'analysis_summary.json': h.dump(summary),
                 'base_descriptive_by_condition.csv': csv_bytes(descriptive(state['base'], ALL, 'Base-1000')),
                 'rq1_secondary_dimensions.csv': csv_bytes(descriptive(state['rq1_rows'], RQ1, 'RQ1_common_complete_case_999')),
                 'rq1_context_sufficiency.csv': csv_bytes(rq1), 'rq2_policy_comparisons.csv': csv_bytes(rq2),
                 'rq2_construct_model.json': h.dump(model), 'rq2_holm_family.csv': csv_bytes(rq2_family),
                 'rq3_predicted_vs_full.csv': csv_bytes([rq3]), 'rq4_mechanism_interactions.csv': csv_bytes(rq4),
                 'analysis_integrity.json': h.dump(integrity)}
    return artifacts, integrity


def commit(state, artifacts, integrity, np):
    s = state['s']; h = state['h']; s.stable()
    artifacts['source_artifact_hashes.json'] = h.dump({'artifacts': s.records, 'canonical_payloads_read': False,
        'source_scope': 'Hash-bound analysis inputs, predictors, frozen cohort/group/identity sources and pinned implementation modules only.'})
    manifest = {'status': STATUS, 'version': 'core_stage', 'gate_runner_path': 'experiments/formal_analysis_gate.py',
                'gate_runner_sha256': MODULES['formal_analysis_gate'],
                'gate_previous_block_reason': 'MISSING_FROZEN_CONSTRUCT_PREDICTOR_ARTIFACT',
                'gate_previous_block_quality_scores_read': False, 'gate_previous_block_output_created': False,
                'implementation_completion': 'New full frozen statistical execution plus explicitly hash-bound predictor linkage; gate_stage unchanged.',
                'analysis_input_manifest_sha256': INPUT_SHA, 'construct_predictor_manifest_sha256': PRED_SHA,
                'construct_predictor_rows': 5000, 'construct_predictor_targets': 1000,
                'construct_predictor_file': state['predictor_path'].relative_to(ROOT).as_posix(),
                'scientific_protocol_changed': False, 'analysis_cohort_changed': False, 'hypothesis_changed': False,
                'multiplicity_changed': False, 'bootstrap_protocol_changed': False,
                'formal_judge_execution_remains_closed': True, 'further_Judge_calls_authorized': False,
                'bootstrap': state['decisions']['bootstrap_test_details'], 'confirmatory_families': state['decisions']['confirmatory_families'],
                'shared_bootstrap_draws_sha256': integrity['shared_bootstrap_draws_sha256'],
                'runtime': {'python': sys.version, 'executable': sys.executable, 'numpy': np.__version__,
                            'solver': 'numpy.linalg.lstsq, rcond=None, float64, full-model weighted FWL'},
                'statistical_non_estimability_is_reported_not_silently_repaired': True,
                'protocol_details_source_sha256': DECISION_SHA, 'script_sha256': s.records[SELF.relative_to(ROOT).as_posix()]['sha256'],
                'determinism': 'Frozen ordering and shared PCG64 draws; sorted JSON/CSV columns, LF; no wall-clock fields. Floating arithmetic runtime recorded.',
                'commit_rule': 'All RQ outputs computed before mkdir; O_EXCL; manifest last; partial output never repaired.',
                'artifact_hashes': {name: digest(raw) for name, raw in artifacts.items()}, **FLAGS, 'output_created': True}
    artifacts['protocol_manifest.json'] = h.dump(manifest)
    artifacts['checksums.sha256'] = ''.join(f'{digest(raw)}  {name}\n' for name, raw in sorted(artifacts.items())).encode()
    require(set(artifacts) == FILES, 'RESULT_FILE_SET_MISMATCH')
    require(not os.path.lexists(OUT), 'OUTPUT_ALREADY_EXISTS')
    s.stable(); os.mkdir(h.safe(OUT), 0o700); FLAGS['output_created'] = True; h.sync_dir(OUT.parent)
    for name in sorted(FILES - {'protocol_manifest.json'}) + ['protocol_manifest.json']:
        if name == 'protocol_manifest.json':
            s.stable()
        fd = os.open(h.safe(OUT / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(artifacts[name]); stream.flush(); os.fsync(stream.fileno())
    h.sync_dir(OUT)
    require({p.name for p in OUT.iterdir()} == FILES, 'FINAL_OUTPUT_INVENTORY')
    for name, raw in artifacts.items():
        require(h.record(OUT / name)['sha256'] == digest(raw), 'FINAL_OUTPUT_CHECKSUM')
    s.stable()
    print(json.dumps({'status': STATUS, 'manifest_sha256': digest(artifacts['protocol_manifest.json']),
                      'output_directory': str(OUT), **FLAGS}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        print('NO_RUN_REQUESTED'); return
    require(sys.executable == PYTHON and Path.cwd() == ROOT and ROOT.resolve() == ROOT and Path(__file__).absolute() == SELF,
            'EXACT_INTERPRETER_ROOT_SCRIPT_REQUIRED')
    require(not os.path.lexists(OUT), 'OUTPUT_ALREADY_EXISTS')
    sys.addaudithook(guard)
    state = prepare(load_modules())
    import numpy as np
    synthetic_checks(np)
    load_outcomes(state)
    artifacts, integrity = calculate(state, np)
    commit(state, artifacts, integrity, np)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        reason = str(exc) if isinstance(exc, Blocked) else 'FROZEN_SOURCE_SCHEMA_NUMERICAL_OR_DURABILITY_FAILURE'
        missing = ('required frozen field: ' + str(exc.args[0])) if isinstance(exc, KeyError) else None
        print(json.dumps({'status': 'BLOCKED', 'reason': reason,
                          'missing_protocol_detail': missing or (reason if 'PROTOCOL' in reason or 'DETAIL' in reason else None),
                          'exception_type': type(exc).__name__, 'partial_output_may_exist': FLAGS['output_created'],
                          **FLAGS}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
