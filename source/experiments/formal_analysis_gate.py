#!/usr/bin/env python3
"""Fail-closed formal-analysis prerequisite gate for the pinned gate_stage sources.

The authoritative construct freeze defines S/M but does not materialize or
bind a five-condition predictor table. Therefore this version MUST block the
entire analysis before reading outcomes. It does not implement a partial RQ
analysis or pretend that a missing beta_M test has been performed.

No --run: no project reads/writes. --run: read-only source verification and an
explicit BLOCKED report, with no output directory or statistical results.
Completion requires separately authorized, hash-bound construct inputs and a
new implementation; this file must not discover or adopt later files silently.
Reuse only pinned strict JSON/hash/bundle utilities from the existing builders.
"""
import argparse
from collections import Counter
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
from repro_paths import PROJECT_ROOT as ROOT, PYTHON
SELF = ROOT / 'experiments/formal_analysis_gate.py'
OUT = ROOT / 'outputs/formal_analysis_gate'
INPUT = ROOT / 'inputs/judge_analysis'
FREEZE = ROOT / 'protocols'
INPUT_SHA = '49bd94437e0a5323d8a647e441120bf2fb6f376c36887aba87a8d9e12e2a6cbc'
PINS = {
    'evaluation': '0456f7aa2c3adc8b3fca866b473306f996909809e395f6cdfa6a097e91db5960',
    'construct_scope': '27d1b4c1c2d2fe31846bfed73b4ba810c8615421b9287132136a5350767bbbf3',
    'construct_definition': '5af93f5d66267cb65b8751f4b7dad2946b0fe9a04d34fa99aebaadd24331e27c',
    'judge_terminal_policy': 'decb522401f7452518534b867177fa87cca73f7e1239bcfa155f4e2fa8257490',
    'cohort': 'd3b0ce6291621f9b267de6a9ba09e3016c5035bc493f7f0f9a0e1c69893d9202'}
HELPERS = {
    'judge_closeout': 'eac035c0dac6c4ac14288c26b5dd960d0579f2ab623d6fbfe8454b6038f23ad9',
    'analysis_input': '4b8f627d22d01c73dfd125adccb7a379cfdefa78f47462c6cf39177c3dccdbdf'}
TERMINAL = 'd4d357fc531cf9c9b2af0e9a83d3967e701ac53096d3872ee76dd2cc05ba9e37'
ZERO = {'quality_scores_read': False, 'descriptive_statistics_computed': False,
        'inferential_statistics_computed': False, 'research_effect_direction_inspected': False,
        'API_calls': 0, 'Judge_calls': 0, 'generation_calls': 0, 'output_created': False}


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def readonly_guard(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn')) or event in (
            'os.mkdir', 'os.remove', 'os.rename', 'os.rmdir', 'os.link', 'os.symlink',
            'os.chmod', 'os.chown', 'os.utime', 'os.truncate', 'os.system', 'os.fork', 'os.kill', 'os.killpg'):
        raise RuntimeError('READ_ONLY_PREREQUISITE_GATE')
    if event == 'open' and args[2] & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND):
        raise RuntimeError('READ_ONLY_PREREQUISITE_GATE')


def check_sources():
    require(sys.executable == PYTHON and Path.cwd() == ROOT and ROOT.resolve() == ROOT and
            Path(__file__).absolute() == SELF, 'EXACT_INTERPRETER_ROOT_SCRIPT_REQUIRED')
    require(not os.path.lexists(OUT), 'OUTPUT_ALREADY_EXISTS')
    for name, pin in HELPERS.items():
        p = ROOT / 'experiments' / (name + '.py')
        require(p.resolve() == p and hashlib.sha256(p.read_bytes()).hexdigest() == pin, 'PINNED_HELPER_MISMATCH')
    helpers = {name: importlib.import_module(name) for name in HELPERS}
    for name, module in helpers.items():
        require(Path(module.__file__).absolute() == ROOT / 'experiments' / (name + '.py'), 'WRONG_HELPER_IMPORT')
    h = helpers['judge_closeout']
    a = helpers['analysis_input']
    h.safe(OUT)
    s = a.Sources(h)
    s.track(SELF)
    for name, pin in HELPERS.items():
        s.track(ROOT / 'experiments' / (name + '.py'), pin)
    manifest = s.bundle(INPUT, INPUT_SHA)
    require(manifest['status'] == 'JUDGE_ANALYSIS_INPUT_BUILT' and manifest['valid_score_rows'] == 10365 and
            manifest['base1000_valid_rows'] == 9999 and manifest['rq1_rows'] == 5994 and
            manifest['formal_judge_execution_remains_closed'] is True and manifest['further_Judge_calls_authorized'] is False,
            'ANALYSIS_INPUT_MANIFEST_STATUS_COUNTS_MISMATCH')
    # Opaque bytes only: count lines without parsing any score record.
    for name, expected in (('scores.jsonl', 10365), ('base_scores.jsonl', 9999),
                           ('rq1_scores.jsonl', 5994)):
        p = h.safe(INPUT / name); digest = hashlib.sha256(); count = 0
        with p.open('rb') as stream:
            for line in stream:
                require(line.strip(), 'BLANK_SCORE_INPUT_RECORD')
                digest.update(line); count += 1
        require(count == expected and digest.hexdigest() == manifest['artifact_hashes'][name], 'SCORE_INPUT_HASH_OR_ROW_COUNT_MISMATCH')
    audit = s.read(INPUT / 'integrity_audit.json')
    expected_audit = {'rq1_unique_targets': 999, 'rq1_rows': 5994, 'rq1_rows_per_condition': 999,
                      'rq1_common_complete_case_pass': True, 'rq2_predicted_vs_semantic_complete_pairs': 1000,
                      'rq2_oracle_vs_semantic_complete_pairs': 1000, 'rq3_predicted_vs_full_complete_pairs': 1000,
                      'transcript_id_complete': True, 'identity_join_pass': True, 'score_range_pass': True,
                      'rq4_pair_coverage_pass': True, 'terminal_missing_rows': 1, 'unexpected_missing_rows': 0}
    require(all(audit[k] == v for k, v in expected_audit.items()), 'FROZEN_INPUT_STRUCTURAL_AUDIT_MISMATCH')
    parents = {name: s.bundle(FREEZE / name, pin) for name, pin in PINS.items()}
    evaluation = parents['evaluation']
    require(evaluation['primary_Q'] == '(D1+D2+D3+D4)/4' and evaluation['delta_Q'] == 0.25, 'Q_OR_MARGIN_MISMATCH')
    decisions = s.read(FREEZE / 'evaluation/analysis_decisions.json')
    tests = decisions['bootstrap_test_details']; families = decisions['confirmatory_families']
    require(tests['replicates'] == 5000 and tests['seed'] == 42 and tests['familywise_alpha'] == 0.05,
            'BOOTSTRAP_PROTOCOL_MISMATCH')
    exact_rules = {
        'NI_alternative': 'theta > -0.25',
        'NI_null': 'theta <= -0.25',
        'NI_raw_p': '(1 + count(e_b >= theta_hat + 0.25)) / 5001',
        'RQ2_RQ4_raw_p': '(1 + count(abs(e_b) >= abs(theta_hat))) / 5001',
        'draw_algorithm': 'Sort transcript_id numerically. NumPy Generator(PCG64(42)); draw G integer indices in [0,G) with replacement per replicate, b=1..5000. Use shared draws across all estimands and conditions.',
        'cluster_population': 'All transcript clusters in the shared_16 primary population. Preserve complete eligible targets, fixed condition vectors and fixed group labels with cluster multiplicity.',
        'effect_interval': 'Ordinary two-sided [2.5%,97.5%] percentile interval of theta_star; linear interpolation (type 7). Report separately from NI decision.',
        'Holm': 'Within each frozen RQ family, sort raw p ascending (ties by listed contrast order). p_adj(j)=min(1,max_{l<=j}((m-l+1)*p_(l))). NI passes iff theta_hat > -0.25 and p_adj <= 0.05.'}
    require(all(tests[k] == v for k, v in exact_rules.items()), 'MISSING_OR_CHANGED_FROZEN_INFERENTIAL_DETAIL')
    require({k: families[k]['n_confirmatory_tests'] for k in ('RQ1', 'RQ2', 'RQ3', 'RQ4')} ==
            {'RQ1': 5, 'RQ2': 3, 'RQ3': 1, 'RQ4': 2}, 'HOLM_FAMILY_SIZE_MISMATCH')
    require(families['RQ1']['contrasts'] == ['1-Full', '2-Full', '4-Full', '8-Full', '16-Full'] and
            families['RQ2']['contrasts'] == ['PredictedMI-B8 - Semantic-B8', 'OracleMI-B8 - Semantic-B8', 'beta_M'] and
            families['RQ3']['contrasts'] == ['PredictedMI-B8 - Full'], 'CONFIRMATORY_FAMILY_MEMBERSHIP_MISMATCH')
    require(families['RQ1']['test_type'] == families['RQ3']['test_type'] == 'one_sided_non_inferiority' and
            families['RQ2']['test_type'] == families['RQ4']['test_type'] == 'two_sided_zero_null', 'TEST_DIRECTION_MISMATCH')
    cost = parents['cohort']
    scope = s.read(FREEZE / 'cohort/analysis_scope.json')
    require(scope['RQ2_construct_level_incrementality']['cohort'] == 'Base-1000 only', 'CONSTRUCT_COHORT_MISMATCH')
    terminal_rule = s.read(FREEZE / 'judge_terminal_policy/analysis_missingness_rule.json')
    require(terminal_rule['RQ1']['conditions'] == ['k1', 'k2', 'k4', 'k8 / Recent-B8', 'k16', 'Full'] and
            terminal_rule['RQ1']['excluded_sample_ids'] == ['annomi_t78_target_32'] and
            terminal_rule['RQ1']['expected_target_count_after_terminal_recovery'] == 999 and terminal_rule['trigger_judge_item_id'] == TERMINAL,
            'RQ1_FROZEN_MISSINGNESS_MISMATCH')
    group_reports = {}
    for mode, expected, other in (('recent', {'recent_missed': 3181, 'recent_covered': 131, 'no_oracle_core_selected': 512}, 'k8 / Recent-B8'),
                                  ('semantic', {'semantic_missed': 3230, 'semantic_covered': 82, 'no_oracle_core_selected': 512}, 'Semantic-B8')):
        path = h.safe(ROOT / decisions['mechanism'][mode + '_group_artifact'])
        base = path.parent
        s.bundle(base, cost['parent_manifest_sha256'][base.relative_to(ROOT).as_posix()])
        groups = a.unique(s.lines(path), 'sample_id')
        require(len(groups) == 3824 and dict(Counter(row['mechanism_group'] for row in groups.values())) == expected,
                'FROZEN_RQ4_GROUP_MISMATCH')
        require(scope['RQ4_' + mode + '_mechanism']['groups_source'] == path.relative_to(ROOT).as_posix() and
                scope['RQ4_' + mode + '_mechanism']['enrichment_conditions'] == ['PredictedMI-B8', other],
                'FROZEN_RQ4_COHORT_PAIR_MISMATCH')
        group_reports[mode] = audit['rq4_required_pair_coverage'][mode]
        require(group_reports[mode]['pair_coverage_pass'] is True, 'FROZEN_RQ4_PAIR_COVERAGE_FAILURE')
    definition = s.read(FREEZE / 'construct_definition/construct_definition.json')
    construct = parents['construct_definition']
    require(definition['primary_model'] == decisions['construct']['primary_model_unchanged'] and
            definition['M_is'] == decisions['construct']['M_is_unchanged'] and
            definition['S_is'] == decisions['construct']['S_is_unchanged'], 'CONSTRUCT_OPERATIONAL_DEFINITION_DRIFT')
    require(definition['inference']['cluster'] == 'transcript_id' and definition['inference']['replicates'] == 5000 and
            definition['inference']['seed'] == 42 and definition['inference']['refit_model_per_replicate'] is True and
            definition['primary_model']['target_fixed_effects'] is True and
            definition['primary_model']['selector_condition_fixed_effects'] is True and
            definition['primary_model']['continuous_covariates'] == ['S_is', 'M_is'], 'CONSTRUCT_ESTIMATOR_DRIFT')
    require(construct['S_is_values_materialized'] is False and construct['M_is_values_materialized'] is False and
            definition['S_is_values_materialized'] is False and definition['M_is_values_materialized'] is False,
            'CONSTRUCT_SOURCE_STATE_CHANGED_REQUIRES_NEW_AUTHORIZATION')
    s.stable()
    return {'status': 'BLOCKED', 'reason': 'MISSING_FROZEN_CONSTRUCT_PREDICTOR_ARTIFACT',
            'missing_protocol_detail': 'No authoritative frozen path/hash/schema for a target-by-five-B8-condition S_is/M_is predictor table.',
            'source_evidence': {'construct_manifest_sha256': PINS['construct_definition'],
                                'S_is_values_materialized': False, 'M_is_values_materialized': False,
                                'operational_definitions_recovered': True, 'fixed_effects_estimator_recovered': True},
            'analysis_input_manifest_sha256': INPUT_SHA,
            'protocol_recovery': {'RQ1': 'PASS', 'RQ2_policy': 'PASS', 'RQ2_construct_protocol': 'PASS',
                                  'RQ2_construct_predictor': 'FAIL', 'RQ3': 'PASS', 'RQ4': 'PASS'},
            'bootstrap_replicates': 5000, 'bootstrap_seed': 42, 'bootstrap_cluster': 'transcript_id',
            'bootstrap_cluster_population': 'All shared_16 primary transcript clusters, not only observed cohort clusters.',
            'holm_family_sizes': {'RQ1': 5, 'RQ2': 3, 'RQ4': 2}, 'delta_Q': 0.25,
            'rq4_authorized_pair_coverage': group_reports,
            'partial_RQ_analysis_forbidden': True, 'beta_M_omission_forbidden': True,
            'S_or_M_reconstruction_performed': False,
            'formal_judge_execution_remains_closed': True, 'further_Judge_calls_authorized': False,
            'formal_statistical_analysis_complete': False,
            'completion_status_not_emitted': 'FORMAL_ANALYSIS_GATE_COMPLETE', **ZERO}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        print('NO_RUN_REQUESTED'); return 0
    sys.addaudithook(readonly_guard)
    report = check_sources()
    print(json.dumps(report, sort_keys=True, ensure_ascii=True, allow_nan=False))
    return 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (Exception, KeyboardInterrupt):
        print(json.dumps({'status': 'BLOCKED', 'reason': 'FROZEN_SOURCE_OR_PROTOCOL_VERIFICATION_FAILURE',
                          'details_withheld': True, **ZERO}), file=sys.stderr)
        raise SystemExit(1)
