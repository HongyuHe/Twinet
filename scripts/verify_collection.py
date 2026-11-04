#!/usr/bin/env python3
"""Exercise real SSH sessions and compare monitoring with an unrecorded gateway.

Run on a Linux lab host with python3-paramiko. The two gateway ports must use
the same lab and host key. Only the named validation services are restarted.
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import statistics
import subprocess
import threading
import time
import uuid

import paramiko


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    parser.add_argument('--key', type=Path, required=True)
    parser.add_argument('--spool', type=Path, required=True)
    parser.add_argument('--received', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=2022)
    parser.add_argument('--baseline-port', type=int, default=2023)
    parser.add_argument('--ases', type=int, default=32)
    parser.add_argument('--gateway-unit')
    parser.add_argument('--collector-unit')
    args = parser.parse_args()
    key = paramiko.Ed25519Key.from_private_key_file(str(args.key))
    host_key = paramiko.Ed25519Key.from_private_key_file(str(args.lab / '.twinet/gateway_host_key'))
    run_id = uuid.uuid4().hex
    report = {'run_id': run_id, 'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
              'ases': args.ases, 'checks': {}, 'batches': []}
    binary = Path(__file__).resolve().parent.parent / 'bin/twinet'
    report['version'] = subprocess.check_output([str(binary), 'version'], text=True).strip()
    report['gateway_port'] = args.port

    def connect(group=3, port=None):
        selected_port = port or args.port
        client = paramiko.SSHClient()
        client.get_host_keys().add(f'[127.0.0.1]:{selected_port}', 'ssh-ed25519', host_key)
        client.connect('127.0.0.1', port=selected_port, username=f'group{group}', pkey=key,
                       look_for_keys=False, allow_agent=False, timeout=20, banner_timeout=20)
        return client

    def metas(root):
        return {p.parent.name: json.loads(p.read_text()) for p in root.glob('*/session.json')}

    def events(session):
        return [json.loads(line) for line in (args.spool / session / 'events.jsonl').read_text().splitlines()]

    def wait_for(predicate, seconds=30):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = predicate()
            if result:
                return result
            time.sleep(.1)
        raise AssertionError('Timed out waiting for a validation condition')

    def receive(channel, end):
        data = b''
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if channel.recv_ready():
                data += channel.recv(65536)
                if end in data:
                    return data
            elif channel.closed:
                raise AssertionError(f'Channel closed early: {data[-500:]!r}')
            else:
                time.sleep(.01)
        raise AssertionError(f'Expected {end!r}, got {data[-500:]!r}')

    before = set(metas(args.spool))
    client = connect()
    stdin, stdout, stderr = client.exec_command("ALL printf '\\000twinet-exit:99\\n'; printf '\\377\\000stderr\\n' >&2; exit 7")
    stdin.close()
    expected_out, expected_err = b'\x00twinet-exit:99\n', b'\xff\x00stderr\n'
    assert stdout.read() == expected_out and stderr.read() == expected_err
    assert stdout.channel.recv_exit_status() == 7
    client.close()
    binary_session = next(iter(set(metas(args.spool)) - before))
    binary_events = events(binary_session)
    for kind, expected in [('output', expected_out), ('stderr', expected_err)]:
        actual = b''.join(base64.b64decode(e['data']) for e in binary_events if e['type'] == kind)
        assert actual == expected
    report['checks']['binary_streams_and_exit_status'] = binary_session

    before = set(metas(args.spool))
    client = connect()
    channel = client.invoke_shell(width=80, height=24)
    receive(channel, b'Device number or name: ')
    channel.sendall('ALL\n')
    receive(channel, b':/# ')
    channel.sendall("printf 'collection-" + run_id + "\\n'\n")
    receive(channel, b':/# ')
    channel.sendall('false\n')
    receive(channel, b':/# ')
    channel.sendall('echo EDITEDX\x7f\n')
    edited = receive(channel, b':/# ')
    assert b'EDITED\r\n' in edited
    channel.sendall('ech\tCOMPLETED\n')
    assert b'COMPLETED\r\n' in receive(channel, b':/# ')
    channel.sendall('\x1b[A\n')
    assert b'COMPLETED\r\n' in receive(channel, b':/# ')
    channel.resize_pty(width=123, height=41)
    time.sleep(.1)
    channel.sendall('stty size\n')
    resized = receive(channel, b'41 123')
    if not resized.endswith(b':/# '):
        receive(channel, b':/# ')
    channel.sendall("vtysh -c 'show bgp summary'\n")
    bgp = receive(channel, b':/# ')
    assert b'BGP' in bgp
    channel.sendall('vtysh\n')
    receive(channel, b'all.as3# ')
    channel.sendall('show ip route\n')
    assert b'Codes:' in receive(channel, b'all.as3# ')
    channel.sendall('exit\n')
    receive(channel, b':/# ')
    channel.sendall('exit\n')
    receive(channel, b'Device number or name: ')
    channel.sendall('ALL_host\n')
    receive(channel, b':/# ')
    channel.sendall('echo SECOND_DEVICE\n')
    assert b'SECOND_DEVICE\r\n' in receive(channel, b':/# ')
    channel.sendall('exit\n')
    receive(channel, b'Device number or name: ')
    channel.sendall('exit\n')
    assert channel.recv_exit_status() == 0
    client.close()
    session = next(iter(set(metas(args.spool)) - before))
    journal = events(session)
    commands = [e for e in journal if e['type'] == 'command_start']
    assert any(e['fields'].get('command') == 'false' for e in commands)
    assert any(e['fields'].get('command') == 'echo EDITED' for e in commands)
    assert sum(e['fields'].get('command') == 'echo COMPLETED' for e in commands) == 2
    assert any(e['type'] == 'command_end' and e['fields'].get('exit_code') == 1 for e in journal)
    assert len([e for e in journal if e['type'] == 'device_start']) == 2
    assert any(e['type'] == 'resize' and e['fields']['cols'] == 123 for e in journal)
    report['checks']['interactive'] = {'session': session, 'commands': len(commands), 'passed': True}

    before = set(metas(args.spool))
    client = connect()
    channel = client.invoke_shell()
    receive(channel, b'Device number or name: ')
    channel.sendall('ALL\n')
    receive(channel, b':/# ')
    channel.sendall('exec bash --norc\n')
    receive(channel, b'# ')
    channel.sendall('echo RECORDING_SURVIVES\n')
    assert b'RECORDING_SURVIVES' in receive(channel, b'# ')
    channel.close()
    client.close()
    interrupted = wait_for(lambda: next((m for id, m in metas(args.spool).items()
                                       if id not in before and m['status'] == 'incomplete'), None))
    report['checks']['shell_replacement_and_disconnect'] = interrupted['id']

    def execution_stopped(session):
        ids = [e['fields'].get('execution_id') for e in events(session) if e['type'] == 'device_start']
        if not ids or not ids[-1]:
            return False
        script = 'for f in /proc/[0-9]*/environ; do tr "\\000" "\\n" < "$f" 2>/dev/null; done'
        result = subprocess.run(['docker', 'exec', 'twinet-collection32-as3-all', 'sh', '-c', script], capture_output=True)
        return ('TWINET_STREAM_ID='+ids[-1]).encode() not in result.stdout

    wait_for(lambda: execution_stopped(interrupted['id']))
    report['checks']['disconnect_process_cleanup'] = True

    initial_ids = set(metas(args.spool))

    def batch(concurrency, port, iteration):
        barrier = threading.Barrier(concurrency)
        expected = {}
        lock = threading.Lock()

        def one(index):
            group = index % args.ases + 1
            marker = f'{run_id}-{port}-{iteration}-{index}'
            command = f"printf '{marker}\\n'; head -c 131072 /dev/zero | tr '\\000' x; printf '\\nEND-{marker}\\n'"
            wanted = (marker + '\n' + 'x' * 131072 + '\nEND-' + marker + '\n').encode()
            barrier.wait(timeout=30)
            start = time.monotonic()
            client = connect(group, port)
            stdin, stdout, stderr = client.exec_command('ALL ' + command, timeout=30)
            stdin.close()
            data, errors = stdout.read(), stderr.read()
            status = stdout.channel.recv_exit_status()
            client.close()
            assert status == 0 and not errors and data == wanted, (group, status, len(data), errors)
            with lock:
                expected[command] = (group, wanted)
            return time.monotonic() - start

        start = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
            durations = list(executor.map(one, range(concurrency)))
        wall = time.monotonic() - start
        result = {'concurrency': concurrency, 'recording': port == args.port, 'iteration': iteration,
                  'wall_seconds': wall, 'latency_median_seconds': statistics.median(durations),
                  'latency_p95_seconds': sorted(durations)[int(.95 * (len(durations)-1))],
                  'output_bytes': concurrency * 131072}
        if port == args.port:
            matched = 0
            for id, meta in metas(args.spool).items():
                if id in initial_ids:
                    continue
                journal = events(id)
                command_events = [e for e in journal if e['type'] == 'command_start' and e['fields'].get('source') == 'gateway']
                if len(command_events) != 1:
                    continue
                command = command_events[0]['fields']['argv'][2]
                if command not in expected:
                    continue
                group, wanted = expected[command]
                actual = b''.join(base64.b64decode(e['data']) for e in journal if e['type'] == 'output')
                assert actual == wanted and meta['as'] == group and meta['status'] == 'complete'
                assert [e['seq'] for e in journal] == list(range(1, len(journal)+1))
                matched += 1
            assert matched == concurrency, (matched, concurrency)
            result['verified_recordings'] = matched
        else:
            assert set(metas(args.spool)) == batch.before
        report['batches'].append(result)
        print(json.dumps(result), flush=True)

    for iteration in range(3):
        ports = [args.baseline_port, args.port] if iteration % 2 == 0 else [args.port, args.baseline_port]
        for port in ports:
            batch.before = set(metas(args.spool))
            batch(32, port, iteration)
    for iteration in range(2):
        batch(64, args.port, iteration+10)

    if args.collector_unit:
        subprocess.run(['systemctl', 'stop', args.collector_unit], check=True)
        try:
            previous_remote = set(metas(args.received))
            batch(32, args.port, 20)
            time.sleep(3)
            assert set(metas(args.received)) == previous_remote
        finally:
            subprocess.run(['systemctl', 'start', args.collector_unit], check=True)
        report['checks']['collector_outage'] = True

    if args.gateway_unit:
        before = set(metas(args.spool))
        client = connect()
        channel = client.invoke_shell()
        receive(channel, b'Device number or name: ')
        channel.sendall('ALL\n')
        receive(channel, b':/# ')
        channel.sendall('echo BEFORE_CRASH\n')
        receive(channel, b':/# ')
        subprocess.run(['systemctl', 'kill', '--signal=KILL', '--kill-whom=main', args.gateway_unit], check=True)
        client.close()
        recovered = wait_for(lambda: next((m for id, m in metas(args.spool).items()
                                         if id not in before and m['status'] == 'incomplete'), None), 30)
        report['checks']['gateway_crash'] = recovered['id']
        wait_for(lambda: execution_stopped(recovered['id']))
        report['checks']['crash_process_cleanup'] = True

    def fully_uploaded():
        local, remote = metas(args.spool), metas(args.received)
        return local and all(m['status'] != 'recording' and id in remote and remote[id].get('sha256') == m.get('sha256') for id, m in local.items())

    wait_for(fully_uploaded, 180)
    for id, meta in metas(args.spool).items():
        local = (args.spool / id / 'events.jsonl').read_bytes()
        remote = (args.received / id / 'events.jsonl').read_bytes()
        assert local == remote
        assert hashlib.sha256(local).hexdigest() == meta['sha256']
    report['checks']['all_uploads_byte_identical'] = True
    report['total_sessions'] = len(metas(args.spool))
    report['journal_bytes'] = sum(m['bytes'] for m in metas(args.spool).values())
    report['ended_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print('Validation passed:', args.output)


if __name__ == '__main__':
    main()
