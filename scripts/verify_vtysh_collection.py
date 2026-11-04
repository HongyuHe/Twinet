#!/usr/bin/env python3
"""Validate native vtysh command reports against real SSH and FRR sessions."""
import argparse
import base64
import concurrent.futures
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess
import time
import uuid

import paramiko


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('lab', 'key', 'spool', 'received', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--port', type=int, default=2022)
    parser.add_argument('--baseline-port', type=int, default=2023)
    parser.add_argument('--application-off-port', type=int, default=0)
    parser.add_argument('--application-off-spool', type=Path)
    args = parser.parse_args()
    key = paramiko.Ed25519Key.from_private_key_file(str(args.key))
    host = paramiko.Ed25519Key.from_private_key_file(str(args.lab / '.twinet/gateway_host_key'))
    binary = Path(__file__).resolve().parent.parent / 'bin/twinet'
    run = uuid.uuid4().hex
    report = {'run': run, 'version': subprocess.check_output([str(binary), 'version'], text=True).strip(), 'checks': {}, 'sessions': []}

    def metas():
        return {p.parent.name: json.loads(p.read_text()) for p in args.spool.glob('*/session.json')}

    def events(session):
        return [json.loads(line) for line in (args.spool / session / 'events.jsonl').read_text().splitlines()]

    def connect(group=3, port=None):
        port = port or args.port
        client = paramiko.SSHClient()
        client.get_host_keys().add(f'[127.0.0.1]:{port}', 'ssh-ed25519', host)
        client.connect('127.0.0.1', port=port, username=f'group{group}', pkey=key,
                       look_for_keys=False, allow_agent=False, timeout=20)
        return client

    def wait_for(predicate, timeout=40):
        end = time.monotonic()+timeout
        while time.monotonic() < end:
            result = predicate()
            if result:
                return result
            time.sleep(.05)
        raise AssertionError('Validation condition timed out')

    def receive(channel, pattern):
        output = b''
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            if channel.recv_ready():
                output += channel.recv(65536)
                if re.search(pattern, output):
                    assert b'\x1b]777;twinet=' not in output
                    return output
            elif channel.closed:
                break
            else:
                time.sleep(.01)
        raise AssertionError(f'Expected {pattern!r}: {output[-700:]!r}')

    def finish(before):
        session = wait_for(lambda: next((id for id, m in metas().items() if id not in before and m['status'] != 'recording'), None))
        report['sessions'].append(session)
        return session

    def activity(session):
        data = subprocess.check_output([str(binary), 'collection', 'export', session, '--dir', str(args.spool), '--format', 'activity'])
        return [json.loads(line) for line in data.splitlines() if line]

    before = set(metas())
    client = connect()
    channel = client.invoke_shell()
    receive(channel, rb'Device number or name: ')
    channel.sendall('ALL\n')
    receive(channel, rb':/# ')
    channel.sendall('vtysh\n')
    receive(channel, rb'all\.as3# ')
    commands = ['show version', 'show ip routeX\x7f', 'show ip rou\t', '\x1b[A',
                'configure terminal', 'interface lo', 'description twinet-collection-validation',
                'exit', 'router bgp 3', 'address-family ipv4 unicast', 'exit-address-family',
                'end', 'definitely-invalid-command', 'show', 'show b',
                'configure terminal', 'interface lo', 'no description', 'end', 'write memory']
    for command in commands:
        channel.sendall(command+'\n')
        receive(channel, rb'all\.as3(?:\([^\r\n]*\))?# ')
    channel.sendall('exit\n')
    receive(channel, rb':/# ')
    channel.sendall('exit\n')
    receive(channel, rb'Device number or name: ')
    channel.sendall('exit\n')
    assert channel.recv_exit_status() == 0
    client.close()
    session = finish(before)
    rows = [r for r in activity(session) if r['source'] == 'vtysh_reported']
    assert len(rows) == len(commands)+1, [(r['command'], r.get('result_name')) for r in rows]
    assert all(r['status'] == 'complete' and 'exit_code' not in r and 'parent_command_id' not in r for r in rows)
    assert sum(r['command'].strip() == 'show ip route' for r in rows) == 3
    assert {0, 2, 3, 4}.issubset({r['result_code'] for r in rows}), [(r['command'], r['result_code']) for r in rows]
    assert any(r['mode_before'] != r['mode_after'] for r in rows if r['command'] == 'configure terminal')
    assert any(r['command'] == 'exit' and r['result_code'] == 0 for r in rows)
    report['checks']['interactive_editing_history_modes_results_exit'] = session

    def direct(command, group=3, port=None):
        client = connect(group, port)
        stdin, stdout, stderr = client.exec_command('ALL '+command, timeout=30)
        stdin.close()
        output, errors = stdout.read(), stderr.read()
        code = stdout.channel.recv_exit_status()
        client.close()
        assert b'\x1b]777;twinet=' not in output+errors
        return code, output, errors

    before = set(metas())
    command = "/usr/bin/vtysh -c 'show version' -c 'show ip route' >/tmp/twinet-vtysh-check 2>/dev/null; cat /tmp/twinet-vtysh-check; rm /tmp/twinet-vtysh-check"
    assert direct(command)[0] == 0
    session = finish(before)
    rows = [r for r in activity(session) if r['source'] == 'vtysh_reported']
    assert [r['command'] for r in rows] == ['show version', 'show ip route']
    assert all(r['input_kind'] == 'argument' and r['result_code'] == 0 and r.get('parent_command_id') for r in rows)
    report['checks']['absolute_path_and_redirection'] = session

    before = set(metas())
    assert direct("bash --norc -c \"vtysh -c 'show version' & vtysh -c 'show ip route' & wait\"")[0] == 0
    session = finish(before)
    rows = [r for r in activity(session) if r['source'] == 'vtysh_reported']
    assert len(rows) == 2 and len({r['invocation'] for r in rows}) == 2
    assert all(r['result_code'] == 0 for r in rows)
    report['checks']['nested_shell_and_concurrent_processes'] = session

    before = set(metas())
    long_command = 'twinet-unknown-'+('x'*5000)
    assert direct("vtysh -c '"+long_command+"'")[0] == 1
    session = finish(before)
    rows = [r for r in activity(session) if r['source'] == 'vtysh_reported']
    assert len(rows) == 1 and rows[0]['command'] == long_command and rows[0]['result_code'] == 2
    report['checks']['fragmented_long_command'] = session

    before = set(metas())
    client = connect()
    channel = client.invoke_shell()
    receive(channel, rb'Device number or name: ')
    channel.sendall('ALL\n')
    receive(channel, rb':/# ')
    channel.sendall("VTYSH_PAGER='sleep 30' vtysh -u\n")
    receive(channel, rb'all\.as3> ')
    channel.sendall('show ip route\n')
    def pending():
        return next((id for id in set(metas())-before if any(e['type'] == 'command_start' and e['fields'].get('source') == 'vtysh_reported' for e in events(id))), None)
    wait_for(pending)
    channel.close()
    client.close()
    session = finish(before)
    rows = [r for r in activity(session) if r['source'] == 'vtysh_reported']
    assert len(rows) == 1 and rows[0]['status'] == 'incomplete' and 'result_code' not in rows[0]
    report['checks']['interrupted_command_has_unknown_result'] = session

    before = set(metas())
    assert direct("vtysh -c 'show version'", port=args.baseline_port)[0] == 0
    assert set(metas()) == before
    report['checks']['recording_disabled'] = True

    if args.application_off_port:
        assert args.application_off_spool is not None
        previous = set(args.application_off_spool.glob('*/session.json'))
        assert direct("vtysh -c 'show version'", port=args.application_off_port)[0] == 0
        files = set(args.application_off_spool.glob('*/session.json'))-previous
        assert len(files) == 1
        metadata = json.loads(next(iter(files)).read_text())
        assert metadata['status'] == 'complete' and not metadata['application_events']
        journal = [json.loads(line) for line in next(iter(files)).with_name('events.jsonl').read_text().splitlines()]
        assert not any(e.get('fields', {}).get('source') == 'vtysh_reported' or e['type'].startswith('application_') for e in journal)
        report['checks']['application_capture_opt_out'] = metadata['id']

    before = set(metas())
    def one(index):
        start = time.monotonic()
        code, output, _ = direct(f"vtysh -c 'show version' -c 'show ip route' -c 'twinet-invalid-{run}-{index}'", index % 32+1)
        assert code == 1 and b'FRRouting' in output and run.encode() in output
        return time.monotonic()-start
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as pool:
        durations = list(pool.map(one, range(64)))
    report['concurrency'] = {'sessions': 64, 'ases': 32, 'wall_seconds': time.monotonic()-start,
                             'median_seconds': statistics.median(durations), 'p95_seconds': sorted(durations)[60]}
    new = set(metas())-before
    assert len(new) == 64
    intervals = []
    metadata = metas()
    for session in new:
        intervals.extend([(datetime.fromisoformat(metadata[session]['started'].replace('Z', '+00:00')), 1),
                          (datetime.fromisoformat(metadata[session]['ended'].replace('Z', '+00:00')), -1)])
    active, peak = 0, 0
    for _, delta in sorted(intervals):
        active += delta
        peak = max(peak, active)
    report['concurrency']['peak_active_recordings'] = peak
    for session in new:
        rows = [r for r in activity(session) if r['source'] == 'vtysh_reported']
        assert len(rows) == 3 and [r['result_code'] for r in rows] == [0, 0, 2]
        assert rows[-1]['command'].startswith('twinet-invalid-'+run)
        assert all(r['as'] == metas()[session]['as'] and r['device'] == f"as{r['as']}/ALL" for r in rows)
        report['sessions'].append(session)
    def uploaded():
        for session in report['sessions']:
            remote = args.received / session / 'session.json'
            if not remote.exists() or json.loads(remote.read_text()).get('sha256') != metas()[session].get('sha256'):
                return False
        return True
    wait_for(uploaded)
    for session in report['sessions']:
        raw = (args.spool / session / 'events.jsonl').read_bytes()
        assert raw == (args.received / session / 'events.jsonl').read_bytes()
        assert hashlib.sha256(raw).hexdigest() == metas()[session]['sha256']
        events_json = events(session)
        assert [e['seq'] for e in events_json] == list(range(1, len(events_json)+1))
        streams = b''.join(base64.b64decode(e.get('data', '')) for e in events_json if e['type'] in ('output', 'stderr'))
        assert b'\x1b]777;twinet=' not in streams
    report['checks']['exact_uploads_and_clean_replay'] = True
    report['completed_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['concurrency']))
    print('vtysh validation passed:', args.output)


if __name__ == '__main__':
    main()
