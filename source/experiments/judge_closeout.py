#!/usr/bin/env python3
"""Freeze technical execution closeout only; never decode canonical contents.

Without --freeze, no project reads or writes occur. Coverage is reconstructed
from frozen target IDs and nonempty canonical filenames in their proper shards.
This is not a replacement for a content-level scientific integrity audit.
"""
import argparse
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sys

sys.dont_write_bytecode = True
from repro_paths import PROJECT_ROOT as ROOT, PYTHON
SELF = ROOT / 'experiments/judge_closeout.py'
TERMINAL_POLICY = ROOT / 'protocols/judge_terminal_policy'
CONTINUATION_POLICY = ROOT / 'protocols/judge_continuation'
TERMINAL_POLICY_SHA = 'decb522401f7452518534b867177fa87cca73f7e1239bcfa155f4e2fa8257490'
RUNTIME = ROOT / 'inputs/judge_runtime'
OUT = ROOT / 'protocols/judge_closeout'
TERMINAL = 'd4d357fc531cf9c9b2af0e9a83d3967e701ac53096d3872ee76dd2cc05ba9e37'
SAMPLE = 'annomi_t78_target_32'
STATUS = 'FORMAL_JUDGE_EXECUTION_CLOSED'
NAMES = {'execution_closeout.json', 'parent_artifact_hashes.json', 'protocol_manifest.json', 'checksums.sha256'}


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def safe(path):
    p = Path(path)
    require(p.is_absolute() and '..' not in p.parts and p.is_relative_to(ROOT), 'Outside PROJECT_ROOT')
    q = ROOT
    require(not q.is_symlink() and q.resolve() == ROOT, 'Unsafe root')
    for part in p.relative_to(ROOT).parts:
        q = q / part
        require(not q.is_symlink(), 'Symlink forbidden')
    return p


def dump(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    def nonfinite(_):
        raise RuntimeError('Nonfinite JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=nonfinite)


def stamp(path):
    s = safe(path).stat()
    return [s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def record(path):
    p = safe(path)
    require(p.is_file(), 'Missing regular parent')
    before = stamp(p); h = hashlib.sha256()
    with p.open('rb') as stream:
        for block in iter(lambda: stream.read(1048576), b''):
            h.update(block)
    require(stamp(p) == before, 'Parent changed during hashing')
    return {'sha256': h.hexdigest(), 'size_bytes': before[2]}


def tracked(records, path, expected=None):
    rec = record(path); key = path.relative_to(ROOT).as_posix()
    require(expected is None or rec['sha256'] == expected, 'Parent hash mismatch')
    require(key not in records or records[key] == rec, 'Parent changed')
    records[key] = rec
    return rec


def read(records, path):
    raw = safe(path).read_bytes()
    require(digest(raw) == records[path.relative_to(ROOT).as_posix()]['sha256'], 'Tracked source changed')
    return strict(raw)


def bundle(records, base, pin):
    tracked(records, base / 'protocol_manifest.json', pin)
    m = read(records, base / 'protocol_manifest.json')
    require({p.name for p in safe(base).iterdir()} == set(m['artifact_hashes']) | {'protocol_manifest.json', 'checksums.sha256'}, 'Incomplete parent bundle')
    for name, sha in m['artifact_hashes'].items():
        require(re.fullmatch('[A-Za-z0-9_.-]+', name), 'Invalid parent name')
        tracked(records, base / name, sha)
    expected = ''.join(f'{sha}  {name}\n' for name, sha in sorted({**m['artifact_hashes'], 'protocol_manifest.json': pin}.items())).encode()
    require(safe(base / 'checksums.sha256').read_bytes() == expected, 'Parent checksums mismatch')
    tracked(records, base / 'checksums.sha256')
    return m


def rows(records, path):
    raw = safe(path).read_bytes()
    require(digest(raw) == records[path.relative_to(ROOT).as_posix()]['sha256'], 'Target source changed')
    values = [strict(line) for line in raw.splitlines()]
    require(len(values) == len({v['judge_item_id'] for v in values}), 'Duplicate target')
    require(all(re.fullmatch('[0-9a-f]{64}', v['judge_item_id']) and type(v['shard_id']) is int and
                v['shard_id'] in range(8) and v['original_worklist_index'] % 8 == v['shard_id'] for v in values), 'Invalid frozen target identity')
    return {v['judge_item_id']: v for v in values}


def inventory(targets):
    # Deliberately stat-only: never open, parse or aggregate a canonical result.
    seen = {}; files = {}
    for sid in range(8):
        folder = safe(RUNTIME / f'shard_{sid}/canonical')
        require(folder.is_dir(), 'Missing canonical directory')
        for p in folder.iterdir():
            require(safe(p).is_file() and re.fullmatch('[0-9a-f]{64}\.json', p.name), 'Unexpected canonical entry')
            if p.stem not in targets:
                continue
            require(p.stem not in seen and targets[p.stem]['shard_id'] == sid, 'Duplicate or wrong-shard canonical')
            state = stamp(p)
            require(state[2] > 0, 'Empty canonical artifact')
            seen[p.stem] = sid; files[p.relative_to(ROOT).as_posix()] = state
    return seen, files


@contextmanager
def locked(path, directory=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW | (os.O_DIRECTORY if directory else 0)
    fd = os.open(safe(path), flags)
    try:
        require(directory or os.fstat(fd).st_size == 0, 'Invalid existing worker lock')
        fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN); os.close(fd)


def verify(records):
    require(not os.path.lexists(safe(RUNTIME / 'terminal_recovery_stop.json')), 'TERMINAL_POLICY STOP exists')
    m4 = bundle(records, TERMINAL_POLICY, TERMINAL_POLICY_SHA)
    require(m4['status'] == 'JUDGE_TERMINAL_POLICY_FROZEN', 'TERMINAL_POLICY not frozen')
    m3 = bundle(records, CONTINUATION_POLICY, m4['parent_continuation_manifest_sha256'])
    require(m3['status'] == 'JUDGE_CONTINUATION_FROZEN', 'CONTINUATION_POLICY not frozen')
    targets = rows(records, CONTINUATION_POLICY / 'continuation_items.jsonl')
    require(len(targets) == 7882, 'CONTINUATION_POLICY target population differs')
    current, snapshot = inventory(targets)
    require(len(current) == 7881 and set(targets) - set(current) == {TERMINAL}, 'Unexpected canonical/missing population')
    require(all(targets[TERMINAL][k] == v for k, v in {'sample_id': SAMPLE, 'condition': 'k16', 'shard_id': 7}.items()), 'Terminal target identity differs')
    runner = ROOT / 'experiments/judge_terminal_recovery.py'
    runner_sha = tracked(records, runner)['sha256']
    terminal_recovery_items = rows(records, TERMINAL_POLICY / 'terminal_recovery_items.jsonl'); parts = {}
    require(len(terminal_recovery_items) == 496 and TERMINAL not in terminal_recovery_items and set(terminal_recovery_items) <= set(targets), 'TERMINAL_POLICY target population differs')
    for sid, count in ((6, 36), (7, 460)):
        part = rows(records, TERMINAL_POLICY / f'shard_{sid}_items.jsonl')
        require(part == {j: row for j, row in terminal_recovery_items.items() if row['shard_id'] == sid} and len(part) == count and
                all(current.get(j) == sid for j in part), 'TERMINAL_POLICY shard coverage differs')
        require(all(all(part[j][k] == targets[j][k] for k in ('sample_id', 'condition', 'shard_id', 'original_worklist_index', 'request_fingerprint')) for j in part), 'continuation/terminal-recovery target identity differs')
        path = RUNTIME / f'shard_{sid}/terminal_recovery_completion.json'
        tracked(records, path); completion = read(records, path); b = completion['binding']
        require(completion['status'] == 'TERMINAL_RECOVERY_SHARD_COMPLETE' and completion['canonical_items'] == count and
                completion['quality_aggregation'] is False and b['shard_id'] == sid and b['continuation_protocol_role'] == 'terminal_stage' and
                b['terminal_policy_manifest_sha256'] == TERMINAL_POLICY_SHA and b['parent_continuation_manifest_sha256'] == m4['parent_continuation_manifest_sha256'] and
                b['runner_sha256'] == runner_sha and b['frozen_shard_sha256'] == m4['artifact_hashes'][f'shard_{sid}_items.jsonl'], 'Completion binding differs')
        when = datetime.fromisoformat(completion['completed_at'])
        require(when.tzinfo is not None and when >= datetime.fromisoformat(m4['created_at']), 'Invalid completion timestamp')
        parts[str(sid)] = len(part)
    require(sum(parts.values()) == len(terminal_recovery_items) == 496, 'Incomplete TERMINAL_POLICY partition')
    terminal = read(records, TERMINAL_POLICY / 'terminal_technical_invalid.json')
    require(all(terminal[k] == v for k, v in {'status': 'TERMINAL_TECHNICAL_INVALID_UNRESOLVED',
            'judge_item_id': TERMINAL, 'sample_id': SAMPLE, 'condition': 'k16', 'shard_id': 7,
            'additional_attempts_authorized': 0, 'attempt_6_plus_authorized': False, 'canonical_exists': False}.items()), 'Terminal frozen record differs')
    rule = read(records, TERMINAL_POLICY / 'analysis_missingness_rule.json'); rq1 = rule['RQ1']
    require(rq1['common_complete_case_across_conditions'] is True and rq1['conditions'] == ['k1', 'k2', 'k4', 'k8 / Recent-B8', 'k16', 'Full'] and
            rq1['excluded_sample_ids'] == [SAMPLE] and rq1['expected_target_count_after_terminal_recovery'] == 999 and
            rq1['expected_count_requires_terminal_recovery'] is True and rule['trigger_judge_item_id'] == TERMINAL and
            rule['frozen_before_quality_inspection'] is True and rule['quality_based_exclusion'] is False, 'RQ1 rule differs')
    summary = dict(status=STATUS, frozen_target_items=len(targets), canonical_items=len(current),
                   terminal_technical_invalid_items=1, unexpected_missing_items=0, terminal_recovery_target_items=len(terminal_recovery_items),
                   terminal_recovery_completed_items=sum(parts.values()), terminal_recovery_shard_counts=parts, terminal_recovery_stop_exists=False,
                   terminal_judge_item_id=TERMINAL, terminal_sample_id=SAMPLE, terminal_condition='k16',
                   terminal_canonical_exists=False, terminal_additional_attempts_authorized=0,
                   RQ1_common_complete_case_rule_frozen=True, RQ1_expected_targets=rq1['expected_target_count_after_terminal_recovery'],
                   quality_scores_read=False, study_score_aggregation_performed=False, canonical_contents_opened=False,
                   further_Judge_calls_authorized=False, formal_judge_execution_closed=True,
                   API_calls=0, Judge_calls=0, generation_calls=0)
    return summary, targets, snapshot


def sync_dir(path):
    fd = os.open(safe(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_new(name, raw):
    require(name in NAMES, 'Unauthorized output name')
    fd = os.open(safe(OUT / name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())


def main():
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument('--freeze', action='store_true')
    if not parser.parse_args().freeze:
        print('NO_FREEZE_REQUESTED'); return
    require(sys.executable == PYTHON and Path.cwd() == ROOT and Path(__file__).absolute() == SELF, 'Exact interpreter/root/script required')
    require(not os.path.lexists(safe(OUT)), 'Output exists; STOP without repair')
    with ExitStack() as stack:
        for sid in range(8):
            stack.enter_context(locked(RUNTIME / f'shard_{sid}/worker.lock'))
        stack.enter_context(locked(RUNTIME, directory=True))
        records = {}; tracked(records, SELF)
        summary, targets, snapshot = verify(records)
        def stable():
            require(not os.path.lexists(safe(RUNTIME / 'terminal_recovery_stop.json')), 'TERMINAL_POLICY STOP appeared')
            require(inventory(targets)[1] == snapshot, 'Canonical population changed')
            for path, rec in records.items():
                require(record(ROOT / path) == rec, 'Parent changed before commit')
        stable()
        parents = {'artifacts': records, 'canonical_inventory': {'scope': 'frozen_continuation_targets',
                   'method': 'Canonical filenames, proper shard, nonzero size, stat identity; contents never opened.',
                   'file_count': len(snapshot), 'path_stat_inventory_sha256': digest(dump(snapshot))},
                   'quality_scores_read': False, 'canonical_contents_opened': False}
        artifacts = {'execution_closeout.json': dump(summary), 'parent_artifact_hashes.json': dump(parents)}
        manifest = {**summary, 'protocol_name': 'formal_judge_execution_closeout', 'version': 'gate_stage',
                    'created_at': datetime.now(timezone.utc).isoformat(), 'terminal_policy_manifest_sha256': TERMINAL_POLICY_SHA,
                    'script_path': SELF.relative_to(ROOT).as_posix(), 'script_sha256': records[SELF.relative_to(ROOT).as_posix()]['sha256'],
                    'artifact_hashes': {name: digest(raw) for name, raw in artifacts.items()},
                    'commit_rule': 'Manifest last; no-clobber; existing partial output is never repaired.'}
        manifest_raw = dump(manifest)
        hashes = {**manifest['artifact_hashes'], 'protocol_manifest.json': digest(manifest_raw)}
        sums = ''.join(f'{sha}  {name}\n' for name, sha in sorted(hashes.items())).encode()
        os.mkdir(safe(OUT), 0o700); sync_dir(OUT.parent)
        for name, raw in artifacts.items():
            write_new(name, raw)
        write_new('checksums.sha256', sums)
        stable()
        write_new('protocol_manifest.json', manifest_raw); sync_dir(OUT)
        require({p.name for p in OUT.iterdir()} == NAMES, 'Unexpected closeout file set')
        for name, sha in hashes.items():
            require(record(OUT / name)['sha256'] == sha, 'Closeout checksum mismatch')
        require((OUT / 'checksums.sha256').read_bytes() == sums, 'Checksums changed')
        stable()
        print(json.dumps({'status': STATUS, 'manifest_sha256': hashes['protocol_manifest.json'],
                          'API_calls': 0, 'Judge_calls': 0, 'generation_calls': 0}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt):
        print('BLOCKED: closeout precondition, durability or integrity failure; no overwrite or repair.', file=sys.stderr)
        raise SystemExit(1)
