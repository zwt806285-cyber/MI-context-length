#!/usr/bin/env python3
"""Materialize frozen authorized scores only, without statistical inference.

Only --run reads scores or writes output. Reuse pinned closeout utilities for
strict JSON, root containment, streaming hashes and read-only worker locks.
Request fingerprint serialization is copied from freeze_judge_execution
and run_judge_continuation; it never dispatches a request.
"""
import argparse
from collections import Counter
from contextlib import ExitStack
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from repro_paths import PROJECT_ROOT as ROOT, PYTHON
SELF = ROOT / 'experiments/analysis_input.py'
OUT = ROOT / 'inputs/judge_analysis'
RUNTIME = ROOT / 'inputs/judge_runtime'
FREEZE = ROOT / 'protocols'
CLOSE = FREEZE / 'judge_closeout'
COST = FREEZE / 'cohort'
EVAL = FREEZE / 'evaluation'
WORK = FREEZE / 'judge_worklist'
TERMINAL_POLICY = FREEZE / 'judge_terminal_policy'
PINS = {
    'closeout': 'dbcfb8523e703b124e7a6b39e114efdf35e7dfe27da0178e522dd095428f0c55',
    'cost_containment': 'd3b0ce6291621f9b267de6a9ba09e3016c5035bc493f7f0f9a0e1c69893d9202',
    'evaluation_protocol': '0456f7aa2c3adc8b3fca866b473306f996909809e395f6cdfa6a097e91db5960',
    'judge_worklist': 'dd1b7147cd631bd04c065553fca24ea8ca6e3ebefc515c62ea7ee69bec50cf83',
    'terminal_stage': 'decb522401f7452518534b867177fa87cca73f7e1239bcfa155f4e2fa8257490'}
HELPER = 'judge_closeout'
HELPER_SHA = 'eac035c0dac6c4ac14288c26b5dd960d0579f2ab623d6fbfe8454b6038f23ad9'
TERMINAL = 'd4d357fc531cf9c9b2af0e9a83d3967e701ac53096d3872ee76dd2cc05ba9e37'
TERMINAL_SAMPLE = 'annomi_t78_target_32'
CONDITIONS = ('k1', 'k2', 'k4', 'k8 / Recent-B8', 'k16', 'Full',
              'Random-B8', 'Semantic-B8', 'PredictedMI-B8', 'OracleMI-B8')
RQ1 = CONDITIONS[:6]
SCORE_FIELDS = ('D1_contextual_grounding', 'D2_mi_adherence', 'D3_motivational_attunement',
                'D4_therapeutic_helpfulness', 'D5_naturalness_coherence')
OUTPUTS = {'scores.jsonl', 'base_scores.jsonl',
           'rq1_scores.jsonl', 'terminal_missing.json', 'integrity_audit.json',
           'source_artifact_hashes.json', 'protocol_manifest.json', 'checksums.sha256'}
STATUS = 'JUDGE_ANALYSIS_INPUT_BUILT'


def require(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def compact(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':')) + '\n').encode()


def no_network(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn')) or event in ('os.system', 'os.fork'):
        raise RuntimeError('Network/process execution forbidden')


class Sources:
    def __init__(self, helper):
        self.h = helper
        self.records = {}

    def track(self, path, sha=None):
        return self.h.tracked(self.records, self.h.safe(path), sha)

    def read(self, path):
        return self.h.read(self.records, path)

    def lines(self, path):
        path = self.h.safe(path); expected = self.records[path.relative_to(ROOT).as_posix()]['sha256']
        sha = hashlib.sha256(); before = self.h.stamp(path)
        with path.open('rb') as stream:
            for line in stream:
                sha.update(line)
                require(line.strip(), 'Blank JSONL record')
                yield self.h.strict(line)
        require(sha.hexdigest() == expected and self.h.stamp(path) == before, 'JSONL changed')

    def bundle(self, base, pin):
        self.track(base / 'protocol_manifest.json', pin)
        manifest = self.read(base / 'protocol_manifest.json')
        hashes = manifest.get('artifact_hashes', manifest.get('artifact_sha256'))
        require(type(hashes) is dict, 'Unknown frozen bundle schema')
        require({p.name for p in self.h.safe(base).iterdir()} == set(hashes) | {'protocol_manifest.json', 'checksums.sha256'}, 'Incomplete frozen bundle')
        for name, sha in hashes.items():
            require(re.fullmatch('[A-Za-z0-9_.-]+', name), 'Invalid frozen artifact path')
            self.track(base / name, sha)
        raw = self.h.safe(base / 'checksums.sha256').read_bytes(); checks = {}
        for line in raw.decode('ascii').splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9_.-]+)', line)
            require(match and match[2] not in checks, 'Invalid checksum file')
            checks[match[2]] = match[1]
        require(checks == {**hashes, 'protocol_manifest.json': pin}, 'Frozen checksums mismatch')
        self.track(base / 'checksums.sha256')
        return manifest

    def stable(self):
        for rel, rec in self.records.items():
            require(self.h.record(ROOT / rel) == rec, 'Source changed before commit')


def unique(rows, key):
    result = {}
    for row in rows:
        value = row[key]
        require(value not in result, 'Duplicate frozen identity')
        result[value] = row
    return result


def canonical_index(h, authorized):
    found = {}; signatures = {}
    for sid in range(8):
        folder = h.safe(RUNTIME / f'shard_{sid}/canonical')
        require(folder.is_dir(), 'Missing canonical folder')
        for path in folder.iterdir():
            # Out-of-union canonical contents and scores are never opened.
            if path.stem not in authorized:
                continue
            require(path.name == path.stem + '.json' and h.safe(path).is_file(), 'Invalid canonical filename')
            require(path.stem not in found and authorized[path.stem]['shard_id'] == sid, 'Duplicate/wrong-shard authorized canonical')
            require(h.stamp(path)[2] > 0, 'Empty canonical file')
            found[path.stem] = path
            signatures[path.relative_to(ROOT).as_posix()] = h.stamp(path)
    require(set(authorized) - set(found) == {TERMINAL} and len(found) == 10365, 'Authorized missing population differs')
    return found, signatures


def frozen_membership(s):
    close = s.bundle(CLOSE, PINS['closeout'])
    closed = s.read(CLOSE / 'execution_closeout.json')
    expected = {'status': 'FORMAL_JUDGE_EXECUTION_CLOSED', 'frozen_target_items': 7882, 'canonical_items': 7881,
                'terminal_technical_invalid_items': 1, 'unexpected_missing_items': 0,
                'further_Judge_calls_authorized': False, 'formal_judge_execution_closed': True,
                'terminal_judge_item_id': TERMINAL, 'terminal_sample_id': TERMINAL_SAMPLE, 'terminal_condition': 'k16'}
    require(all(close[k] == v and closed[k] == v for k, v in expected.items()), 'Closeout mismatch')
    require(close['script_sha256'] == HELPER_SHA, 'Closeout helper binding mismatch')
    cost = s.bundle(COST, PINS['cost_containment'])
    evaluation = s.bundle(EVAL, PINS['evaluation_protocol'])
    work = s.bundle(WORK, PINS['judge_worklist'])
    require(cost['status'] == 'COST_COHORT_FROZEN' and cost['final_union_unique_items'] == 10366,
            'Cost-containment cohort not frozen')
    require(evaluation['status'] == 'EVALUATION_PROTOCOL_FROZEN' and evaluation['primary_Q'] == '(D1+D2+D3+D4)/4', 'Evaluation definition drift')
    require(work['status'] == 'JUDGE_WORKLIST_FROZEN' and work['judge_worklist_rows'] == 38240, 'Worklist protocol drift')
    terminal_stage = s.bundle(TERMINAL_POLICY, PINS['terminal_stage'])
    require(close['terminal_policy_manifest_sha256'] == PINS['terminal_stage'], 'Closeout ancestry drift')
    require(not os.path.lexists(s.h.safe(RUNTIME / 'terminal_recovery_stop.json')), 'TERMINAL_POLICY STOP exists')
    terminal = s.read(TERMINAL_POLICY / 'terminal_technical_invalid.json')
    require(all(terminal[k] == v for k, v in {'judge_item_id': TERMINAL, 'sample_id': TERMINAL_SAMPLE,
            'condition': 'k16', 'status': 'TERMINAL_TECHNICAL_INVALID_UNRESOLVED', 'canonical_exists': False,
            'additional_attempts_authorized': 0, 'attempt_6_plus_authorized': False}.items()), 'Terminal identity/status drift')
    rule = s.read(TERMINAL_POLICY / 'analysis_missingness_rule.json')['RQ1']
    require(rule['common_complete_case_across_conditions'] is True and rule['conditions'] == list(RQ1) and
            rule['excluded_sample_ids'] == [TERMINAL_SAMPLE] and rule['expected_target_count_after_terminal_recovery'] == 999, 'RQ1 missingness drift')
    authorized = unique(s.lines(COST / 'final_authorized_items.jsonl'), 'judge_item_id')
    require(len(authorized) == 10366, 'Final union count differs')
    sets = {}
    for short, file in {'base': 'base_1000_items.jsonl', 'semantic': 'rq4_semantic_enrichment_items.jsonl',
                        'recent': 'rq4_recent_enrichment_items.jsonl', 'human': 'human_120_items.jsonl'}.items():
        part = unique(s.lines(COST / file), 'judge_item_id')
        require(set(part) <= set(authorized) and all(part[j] == authorized[j] for j in part), 'Membership record drift')
        sets[short] = set(part)
    require(set(authorized) == set.union(*sets.values()) and len(sets['base']) == 10000 and len(sets['human']) == 120, 'Frozen component union mismatch')
    expected_fields = {'base': 'membership_base_1000', 'semantic': 'membership_rq4_semantic',
                       'recent': 'membership_rq4_recent', 'human': 'membership_human_120'}
    for jid, row in authorized.items():
        require(re.fullmatch('[0-9a-f]{64}', jid) and row['condition'] in CONDITIONS and type(row['worklist_index']) is int and
                type(row['shard_id']) is int and row['shard_id'] == row['worklist_index'] % 8, 'Invalid authorized identity')
        require(all(type(row[field]) is bool and row[field] is (jid in sets[key]) for key, field in expected_fields.items()), 'Membership flag mismatch')
    require(TERMINAL in sets['base'] and TERMINAL not in sets['human'] and
            authorized[TERMINAL]['sample_id'] == TERMINAL_SAMPLE and authorized[TERMINAL]['condition'] == 'k16', 'Terminal membership differs')
    base_order = list(unique(s.lines(COST / 'base_1000_targets.jsonl'), 'sample_id'))
    require(len(base_order) == 1000 and set(base_order) == {authorized[j]['sample_id'] for j in sets['base']}, 'Base target order/population mismatch')
    for rank, row in enumerate(s.lines(COST / 'base_1000_targets.jsonl'), 1):
        require(row['selection_rank'] == rank, 'Frozen Base target rank mismatch')
    pairs = unique(authorized.values(), 'judge_item_id')
    pair_ids = {}
    for jid, row in pairs.items():
        key = (row['sample_id'], row['condition'])
        require(key not in pair_ids, 'Duplicate sample/condition')
        pair_ids[key] = jid
    require(all(pair_ids.get((sample, condition)) in sets['base'] for sample in base_order for condition in CONDITIONS), 'Base ten-condition incompleteness')
    return {'cost': cost, 'eval': evaluation, 'work': work, 'terminal_stage': terminal_stage, 'authorized': authorized,
            'sets': sets, 'base_order': base_order, 'pair_ids': pair_ids}


def join_identities(s, state):
    authorized = state['authorized']; identities = {}; all_ids = []; transcripts = {}
    for index, row in enumerate(s.lines(WORK / 'identities.jsonl')):
        jid = row['judge_item_id']; all_ids.append(jid)
        if jid not in authorized:
            continue
        a = authorized[jid]
        require(jid not in identities and a['worklist_index'] == index and
                all(row[k] == a[k] for k in ('sample_id', 'condition', 'internal_condition_id')), 'Identity map join mismatch')
        transcript = row.get('transcript_id')
        require(type(transcript) is str and bool(transcript.strip()) and type(row['sample_id']) is str and bool(row['sample_id']), 'Missing frozen transcript/sample identity')
        sample = row['sample_id']
        require(sample not in transcripts or transcripts[sample] == transcript, 'Ambiguous sample/transcript mapping')
        transcripts[sample] = transcript
        identities[jid] = {'judge_item_id': jid, 'sample_id': sample, 'transcript_id': transcript,
                           'condition': row['condition'], 'internal_condition_id': row['internal_condition_id'],
                           'original_worklist_index': index, 'shard_id': a['shard_id']}
    require(len(all_ids) == len(set(all_ids)) == 38240 and set(identities) == set(authorized), 'Identity population mismatch')
    human = unique(s.lines(WORK / 'human_validation_identities.jsonl'), 'judge_item_id')
    require(set(human) == state['sets']['human'], 'Human-120 frozen source differs')
    for jid, row in human.items():
        require(all(row[k] == identities[jid][k] for k in ('sample_id', 'condition', 'transcript_id')), 'Human identity drift')
    return identities, all_ids, transcripts


def fingerprints(s, state, all_ids):
    original_base = FREEZE / 'judge_execution'
    pin = state['cost']['parent_manifest_sha256'][original_base.relative_to(ROOT).as_posix()]
    s.bundle(original_base, pin)
    config = s.read(original_base / 'judge_execution_contract.json')
    require(config['requested_model'] == config['allowed_returned_model_identity'] == 'claude-opus-4-8' and
            config['temperature'] == 0 and config['max_tokens'] == 256 and
            config['system_prompt_sha256'] == state['work']['judge_system_prompt_sha256'], 'Frozen Judge config drift')
    schema = config['output_schema']['schema']
    require(set(schema) == set(SCORE_FIELDS) | {'critical_violation'}, 'Frozen structured score fields differ')
    rubric = s.read(EVAL / 'judge_rubric.json'); primary = rubric['primary_quality']
    require(primary['formula'] == '(D1 + D2 + D3 + D4) / 4' and primary['D5_included'] is False and
            primary['critical_violation_included'] is False and rubric['D5_role'] == 'secondary_only' and
            rubric['critical_violation']['type'] == 'boolean', 'Frozen scoring definition differs')
    require(all(rubric['dimensions'][f'D{i}']['type'] == 'integer' and rubric['dimensions'][f'D{i}']['minimum'] == 1 and
                rubric['dimensions'][f'D{i}']['maximum'] == 5 for i in range(1, 6)), 'Frozen scoring scale differs')
    prompt_path = WORK / 'judge_system_prompt.txt'
    s.track(prompt_path, config['system_prompt_sha256']); prompt = s.h.safe(prompt_path).read_text(encoding='utf-8')
    path = WORK / 'blind_worklist.jsonl'
    require(s.records[path.relative_to(ROOT).as_posix()]['sha256'] == config['worklist_sha256'], 'Frozen blind hash drift')
    results = {}; count = 0
    for index, item in enumerate(s.lines(path)):
        count += 1
        require(index < len(all_ids) and item['judge_item_id'] == all_ids[index], 'Blind/identity order mismatch')
        jid = item['judge_item_id']
        if jid not in state['authorized']:
            continue
        require(set(item) == {'judge_item_id', 'full_history', 'candidate_response'}, 'Blind schema differs')
        history = item['full_history']
        require(type(history) is list and history and history[-1]['role'] == 'client' and
                all(set(u) == {'role', 'text'} and u['role'] in ('client', 'therapist') and type(u['text']) is str for u in history), 'Blind history schema differs')
        require(type(item['candidate_response']) is str and item['candidate_response'].strip(), 'Invalid frozen candidate')
        user = compact({'FULL PRE-TARGET HISTORY': history, 'CANDIDATE THERAPIST RESPONSE': item['candidate_response']}).decode()
        request = {'model': config['requested_model'], 'temperature': 0, 'max_tokens': 256,
                   'messages': [{'role': 'system', 'content': prompt}, {'role': 'user', 'content': user}]}
        results[jid] = hashlib.sha256(compact({'judge_item_id': jid, 'endpoint': config['endpoint'], 'request': request})).hexdigest()
    require(count == 38240 and set(results) == set(state['authorized']), 'Blind join incomplete')
    return results, config


def rq4_audit(s, state, transcripts, available):
    scope = s.read(COST / 'analysis_scope.json'); decisions = s.read(EVAL / 'analysis_decisions.json')
    audit = {}; all_base = set(state['base_order'])
    for mode, other, parent_name in (('semantic', 'Semantic-B8', 'mechanism_groups'),
                                     ('recent', 'k8 / Recent-B8', 'analysis_scope')):
        design = scope[f'RQ4_{mode}_mechanism']; path = s.h.safe(ROOT / design['groups_source']); parent = FREEZE / parent_name
        require(path.parent == parent and design['enrichment_conditions'] == ['PredictedMI-B8', other] and
                decisions['mechanism'][f'{mode}_group_artifact'] == design['groups_source'], 'Frozen RQ4 source/pair differs')
        pin = state['cost']['parent_manifest_sha256'][parent.relative_to(ROOT).as_posix()]
        s.bundle(parent, pin)
        groups = unique(s.lines(path), 'sample_id')
        require(len(groups) == 3824 and all(g['mechanism_group'] in (mode + '_missed', mode + '_covered', 'no_oracle_core_selected') for g in groups.values()), 'Frozen RQ4 group population differs')
        covered = {sample for sample, row in groups.items() if row['mechanism_group'] == mode + '_covered'}
        enrichment = state['sets'][mode]
        expected_enrichment = {state['pair_ids'].get((sample, condition)) for sample in covered for condition in ('PredictedMI-B8', other)}
        require(None not in expected_enrichment and enrichment == expected_enrichment, 'Frozen enrichment mismatch')
        population = all_base | covered
        require(population <= set(groups), 'RQ4 target missing frozen group')
        required = {sample for sample in population if groups[sample]['mechanism_group'] != 'no_oracle_core_selected'}
        require(all(groups[sample]['transcript_id'] == transcripts[sample] for sample in population), 'RQ4 transcript join mismatch')
        require(all(state['pair_ids'].get((sample, condition)) in available for sample in required for condition in ('PredictedMI-B8', other)), 'RQ4 required pair missing')
        audit[mode] = {'required_targets': len(required), 'complete_pairs': len(required), 'missing_pairs': 0,
                       'conditions': ['PredictedMI-B8', other],
                       'groups': dict(sorted(Counter(groups[sample]['mechanism_group'] for sample in required).items())),
                       'no_oracle_core_selected_targets_not_in_primary_interaction': len(population - required),
                       'frozen_group_source': path.relative_to(ROOT).as_posix(), 'pair_coverage_pass': True}
    return audit


def score_rows(s, state, identities, paths, expected_fp, config):
    rows = {}; provenance = {}; file_signatures = {}
    # Only existing unique canonical records are consumed; no candidate selection.
    for jid in sorted(paths, key=lambda j: identities[j]['original_worklist_index']):
        path = paths[jid]; rec = s.h.record(path); raw = s.h.safe(path).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == rec['sha256'], 'Canonical changed during read')
        value = s.h.strict(raw); identity = identities[jid]
        require(value['judge_item_id'] == jid and type(value['shard_id']) is int and value['shard_id'] == identity['shard_id'] and
                value['requested_model'] == value['returned_model_identity'] == config['requested_model'] and
                value['request_fingerprint'] == expected_fp[jid] and value['quality_based_selection'] is False, 'Canonical technical identity differs')
        require(value['canonical_rule'] in ('first_technically_valid_observed_response', 'first_technically_valid_post_amendment_observed_response',
                                          'first_technically_valid_formal_response'), 'Unknown canonical acceptance rule')
        number = value['attempt_number']
        require(type(number) is int and number > 0, 'Invalid canonical attempt')
        folder = RUNTIME / f"shard_{identity['shard_id']}/attempts" / jid
        evidence = {}
        for kind in ('intent', 'observation'):
            p = folder / f'attempt_{number:02d}_{kind}.json'; evidence_rec = s.h.record(p)
            content = s.h.safe(p).read_bytes()
            require(hashlib.sha256(content).hexdigest() == evidence_rec['sha256'], 'Technical evidence changed')
            evidence[kind] = s.h.strict(content)
            provenance[p.relative_to(ROOT).as_posix()] = evidence_rec
            file_signatures[p.relative_to(ROOT).as_posix()] = s.h.stamp(p)
            require(all(evidence[kind][k] == value[k] for k in ('judge_item_id', 'shard_id', 'attempt_number', 'request_fingerprint', 'requested_model')), 'Canonical attempt binding mismatch')
        intent, obs = evidence['intent'], evidence['observation']
        require(intent['system_prompt_sha256'] == config['system_prompt_sha256'] and
                all(obs[k] is True for k in ('technical_valid', 'request_dispatched', 'http_success', 'API_success', 'observed_provider_response')) and
                obs['returned_model_identity'] == config['allowed_returned_model_identity'] and obs['failure_class'] is None,
                'Canonical lacks technically valid observed response')
        require(all(value[k] == obs[k] for k in ('raw_response_id', 'raw_content_sha256')) and value['observed_at'] == obs['completed_at'], 'Canonical observation provenance differs')
        require(all(type(value[k]) is int and 1 <= value[k] <= 5 for k in SCORE_FIELDS), 'Canonical score schema/range failure')
        require(type(value['critical_violation']) is bool, 'Canonical boolean schema failure')
        q = sum(value[k] for k in SCORE_FIELDS[:4]) / 4
        require(type(value['Q']) in (int, float) and value['Q'] == q, 'Stored Q differs from frozen definition')
        scores = {f'D{i}': value[k] for i, k in enumerate(SCORE_FIELDS, 1)}
        rows[jid] = {**identity, **scores, 'Q': q, 'critical_violation': value['critical_violation'],
                     'base_1000_member': jid in state['sets']['base'], 'rq4_semantic_member': jid in state['sets']['semantic'],
                     'rq4_recent_member': jid in state['sets']['recent'], 'human_120_member': jid in state['sets']['human']}
        provenance[path.relative_to(ROOT).as_posix()] = rec
        file_signatures[path.relative_to(ROOT).as_posix()] = s.h.stamp(path)
        # Raw observations and input text never enter output artifacts or logs.
        del evidence, intent, obs, value, raw
    return rows, provenance, file_signatures


def build(s):
    state = frozen_membership(s)
    paths, canonical_signatures = canonical_index(s.h, state['authorized'])
    identities, all_ids, transcripts = join_identities(s, state)
    fp, config = fingerprints(s, state, all_ids)
    mechanisms = rq4_audit(s, state, transcripts, set(paths))
    rows, canonical_provenance, signatures = score_rows(s, state, identities, paths, fp, config)
    require(len(rows) == 10365, 'Score row count differs')
    base = [rows[state['pair_ids'][(sample, condition)]] for sample in state['base_order'] for condition in CONDITIONS
            if state['pair_ids'][(sample, condition)] in rows]
    expected_counts = {k: 999 if k == 'k16' else 1000 for k in CONDITIONS}
    counts = dict(Counter(row['condition'] for row in base))
    require(len(base) == 9999 and counts == expected_counts and len({row['sample_id'] for row in base}) == 1000, 'Base score coverage differs')
    complete = [sample for sample in state['base_order'] if all(state['pair_ids'][(sample, k)] in rows for k in RQ1)]
    require(len(complete) == 999 and set(state['base_order']) - set(complete) == {TERMINAL_SAMPLE}, 'RQ1 complete-case target mismatch')
    rq1 = [rows[state['pair_ids'][(sample, k)]] for sample in complete for k in RQ1]
    require(len(rq1) == 5994 and Counter(row['condition'] for row in rq1) == {k: 999 for k in RQ1}, 'RQ1 complete-case rows differ')
    pairs = {}
    for name, a, b in (('rq2_predicted_vs_semantic_complete_pairs', 'PredictedMI-B8', 'Semantic-B8'),
                       ('rq2_oracle_vs_semantic_complete_pairs', 'OracleMI-B8', 'Semantic-B8'),
                       ('rq3_predicted_vs_full_complete_pairs', 'PredictedMI-B8', 'Full')):
        n = sum(all(state['pair_ids'][(sample, k)] in rows for k in (a, b)) for sample in state['base_order'])
        require(n == 1000, 'RQ2/RQ3 incomplete pairs'); pairs[name] = n
    require(len(state['sets']['human']) == 120 and state['sets']['human'] <= set(rows), 'Human-120 incomplete')
    audit = {'final_authorized_items': len(state['authorized']), 'valid_score_rows': len(rows),
             'terminal_missing_rows': 1, 'unexpected_missing_rows': 0, 'duplicate_authorized_canonicals': 0,
             'base1000_items': 10000, 'base1000_valid_score_rows': len(base), 'base1000_unique_targets': 1000,
             'base_counts_by_condition': counts, 'rq1_unique_targets': len(complete), 'rq1_rows': len(rq1),
             'rq1_rows_per_condition': 999, 'rq1_common_complete_case_pass': True, **pairs,
             'human120_items': 120, 'human120_judge_scores_available': 120,
             'rq4_required_pair_coverage': mechanisms, 'rq4_pair_coverage_pass': True,
             'score_range_pass': True, 'identity_join_pass': True, 'transcript_id_complete': True,
             'canonical_technical_observation_binding_pass': True, 'frozen_request_fingerprint_pass': True,
             'quality_scores_read': True, 'descriptive_statistics_computed': False, 'inferential_statistics_computed': False,
             'research_effect_direction_inspected': False, 'API_calls': 0, 'Judge_calls': 0, 'generation_calls': 0}
    missing = {**identities[TERMINAL], 'missingness_type': 'TERMINAL_TECHNICAL_INVALID_UNRESOLVED',
               'quality_based_missingness': False, 'canonical_exists': False}
    ordered = [rows[j] for j in sorted(rows, key=lambda j: rows[j]['original_worklist_index'])]
    artifacts = {'scores.jsonl': b''.join(compact(row) for row in ordered),
                 'base_scores.jsonl': b''.join(compact(row) for row in base),
                 'rq1_scores.jsonl': b''.join(compact(row) for row in rq1),
                 'terminal_missing.json': s.h.dump(missing), 'integrity_audit.json': s.h.dump(audit)}
    s.stable()
    source_hashes = {'artifacts': s.records,
                     'canonical_and_backing_attempt_provenance': {
                         'sha256': hashlib.sha256(s.h.dump(canonical_provenance)).hexdigest(),
                         'serialization': 'Sorted path -> {sha256,size_bytes}; sorted-key indent-2 ASCII JSON plus LF.',
                         'canonical_count': len(rows), 'backing_attempt_files': 2 * len(rows),
                         'outside_final_union_canonical_contents_read': False},
                     'source_identity_map_has_transcript_id': True, 'transcript_id_string_parsing_used': False}
    artifacts['source_artifact_hashes.json'] = s.h.dump(source_hashes)
    manifest = {'status': STATUS, 'protocol_name': 'formal_judge_analysis_input', 'version': 'gate_stage',
                **{key + '_manifest_sha256': PINS[key] for key in ('closeout', 'cost_containment', 'evaluation_protocol', 'judge_worklist')},
                'final_authorized_items': len(state['authorized']), 'valid_score_rows': len(rows),
                'base1000_valid_rows': len(base), 'rq1_rows': len(rq1), 'rq1_targets': len(complete),
                'Q_definition': '(D1+D2+D3+D4)/4', 'D5_role': 'secondary',
                'critical_violation_role': 'secondary_no_exclusion', 'quality_scores_read': True,
                'descriptive_statistics_computed': False, 'inferential_statistics_computed': False,
                'research_effect_direction_inspected': False, 'formal_judge_execution_remains_closed': True,
                'further_Judge_calls_authorized': False, 'API_calls': 0, 'Judge_calls': 0, 'generation_calls': 0,
                'script_sha256': s.records[SELF.relative_to(ROOT).as_posix()]['sha256'],
                'ordering': 'Authorized: frozen worklist order. Base/RQ1: frozen Base rank, then fixed condition order.',
                'determinism': 'Canonical ASCII JSON/LF, exact quarter-step Q, no wall-clock timestamp.',
                'commit_rule': 'Manifest last; no-clobber; partial output never overwritten or repaired.',
                'artifact_hashes': {name: hashlib.sha256(raw).hexdigest() for name, raw in artifacts.items()}}
    artifacts['protocol_manifest.json'] = s.h.dump(manifest)
    hashes = {name: hashlib.sha256(raw).hexdigest() for name, raw in artifacts.items()}
    artifacts['checksums.sha256'] = ''.join(f'{sha}  {name}\n' for name, sha in sorted(hashes.items())).encode()

    def stable():
        s.stable()
        require(not os.path.lexists(s.h.safe(RUNTIME / 'terminal_recovery_stop.json')), 'TERMINAL_POLICY STOP appeared')
        require(canonical_index(s.h, state['authorized'])[1] == canonical_signatures, 'Canonical population changed')
        for rel, rec in canonical_provenance.items():
            require(s.h.stamp(ROOT / rel) == signatures[rel] and s.h.record(ROOT / rel) == rec, 'Canonical/attempt source changed')
    return artifacts, stable


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--run', action='store_true')
    if not parser.parse_args().run:
        print('NO_RUN_REQUESTED'); return
    require(sys.executable == PYTHON and Path.cwd() == ROOT and ROOT.resolve() == ROOT and Path(__file__).absolute() == SELF,
            'Exact interpreter/root/script required')
    require(not os.path.lexists(OUT), 'Output exists; STOP')
    helper_path = ROOT / 'experiments' / (HELPER + '.py')
    require(helper_path.resolve() == helper_path and hashlib.sha256(helper_path.read_bytes()).hexdigest() == HELPER_SHA, 'Pinned utility mismatch')
    sys.addaudithook(no_network)
    h = importlib.import_module(HELPER)
    require(Path(h.__file__).absolute() == helper_path, 'Wrong utility import')
    h.safe(OUT)
    with ExitStack() as stack:
        for sid in range(8):
            stack.enter_context(h.locked(RUNTIME / f'shard_{sid}/worker.lock'))
        stack.enter_context(h.locked(RUNTIME, directory=True))
        s = Sources(h); s.track(SELF); s.track(helper_path, HELPER_SHA)
        artifacts, stable = build(s)
        require(set(artifacts) == OUTPUTS, 'Output file set differs')
        stable()
        os.mkdir(h.safe(OUT), 0o700); h.sync_dir(OUT.parent)
        for name in sorted(OUTPUTS - {'protocol_manifest.json'}):
            fd = os.open(h.safe(OUT / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(artifacts[name]); stream.flush(); os.fsync(stream.fileno())
        stable()
        fd = os.open(h.safe(OUT / 'protocol_manifest.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(artifacts['protocol_manifest.json']); stream.flush(); os.fsync(stream.fileno())
        h.sync_dir(OUT)
        require({p.name for p in OUT.iterdir()} == OUTPUTS, 'Unexpected output file')
        for name, raw in artifacts.items():
            require(h.record(OUT / name)['sha256'] == hashlib.sha256(raw).hexdigest(), 'Output checksum failure')
        stable()
        print(json.dumps({'status': STATUS, 'manifest_sha256': hashlib.sha256(artifacts['protocol_manifest.json']).hexdigest(),
                          'valid_score_rows': 10365, 'base1000_valid_rows': 9999, 'rq1_rows': 5994,
                          'API_calls': 0, 'Judge_calls': 0, 'generation_calls': 0}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print('BLOCKED: source, schema, identity, coverage or durability invariant failed; no repair or overwrite.', file=sys.stderr)
        raise SystemExit(1)
