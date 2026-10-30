"""Disposable synthetic integration contracts; never touches host services.

Run only under a restricted OS sandbox with scratch-local HOME/TMPDIR, read-only
source/toolchain, no external network and resource limits. Linux real identities
are a separate opt-in lab procedure, not assumed by these same-UID fixtures.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import struct
import tempfile
import threading
from uuid import uuid4

import pytest

from runtime.query import QueryFailure, QueryStore, serve_connection
from runtime.storage import EventStore


def synthetic_event(device='device-lab', *, marker='nested synthetic secret'):
    return {'event_id':str(uuid4()),'device_id':device,
            'observed_at':datetime.now(timezone.utc).isoformat(),
            'type':'connect','src_ip':'192.0.2.11','proto':'tcp',
            'detail':{'password': marker}}


def store_fixture(path):
    store=EventStore(path,max_bytes=4*1024*1024)
    return store,QueryStore(path)


@pytest.fixture
def short_socket_dir():
    """macOS caps AF_UNIX sun_path at 104 bytes, shorter than pytest's tmp_path."""
    directory=tempfile.mkdtemp(prefix='dq-',dir='/tmp')
    try:
        yield Path(directory)
    finally:
        shutil.rmtree(directory,ignore_errors=True)


def request(operation, **kwargs):
    return {'version':1,'operation':operation,**kwargs}


def read_exact(sock, length):
    out=bytearray()
    while len(out)<length:
        chunk=sock.recv(length-len(out))
        if not chunk:
            raise ConnectionError('closed before framed response')
        out.extend(chunk)
    return bytes(out)


def test_redaction_is_allowlist_not_recursive_regex(tmp_path):
    writer,reader=store_fixture(tmp_path/'events.db')
    secret='<script>synthetic SECRET + =HYPERLINK</script>'
    event=synthetic_event(marker=secret)
    assert writer.ingest('sensor-lab',[event])['accepted']==1
    result=reader.execute(request('list',filters={},limit=25))
    assert result['total']==1 and result['redacted'] is True
    assert set(result['items'][0])=={'sensor','event_id','device','received_at','observed_at','kind','source','proto'}
    assert secret not in json.dumps(result)
    detail=reader.execute(request('detail',sensor='sensor-lab',event_id=event['event_id']))
    assert secret not in json.dumps(detail) and 'payload' not in detail['event']
    exported=reader.execute(request('export',filters={},limit=500))
    assert exported['items']==result['items']
    with sqlite3.connect(tmp_path/'events.db') as db:
        db.execute("UPDATE events SET source='=HYPERLINK(1)' WHERE event_id=?",(event['event_id'],))
    assert reader.execute(request('list',filters={},limit=25))['items'][0]['source']=='<invalid>'


def test_signed_snapshot_cursor_ignores_concurrent_insert(tmp_path):
    writer,reader=store_fixture(tmp_path/'events.db')
    earlier=[synthetic_event() for _ in range(2)]
    writer.ingest('sensor-lab',earlier)
    first=reader.execute(request('list',filters={},limit=1))
    assert first['total']==2 and first['next_cursor']
    newcomer=synthetic_event()
    writer.ingest('sensor-lab',[newcomer])
    second=reader.execute(request('list',filters={},limit=1,cursor=first['next_cursor']))
    assert second['total']==2 and second['offset']==1
    assert {item['event_id'] for item in first['items']+second['items']}=={e['event_id'] for e in earlier}
    with pytest.raises(QueryFailure) as exc:
        reader.execute(request('list',filters={'sensor':'other'},limit=1,cursor=first['next_cursor']))
    assert exc.value.code=='INVALID'
    with pytest.raises(QueryFailure) as exc:
        QueryStore(tmp_path/'events.db').execute(request('list',filters={},limit=1,cursor=first['next_cursor']))
    assert exc.value.code=='INVALID'  # process restart revokes in-memory cursors


def test_strict_bounds_invalid_sql_and_missing_locked_store(tmp_path):
    missing=QueryStore(tmp_path/'missing.db')
    with pytest.raises(QueryFailure) as exc:
        missing.execute(request('list',filters={},limit=1))
    assert exc.value.code=='UNAVAILABLE' and not (tmp_path/'missing.db').exists()
    writer,reader=store_fixture(tmp_path/'events.db')
    for invalid in (request('list',filters={},limit=501),
                    request('list',filters={},limit=1,sql='DROP TABLE events'),
                    request('list',filters={'source':'=1+1'},limit=1),
                    request('list',filters={'from_time':(datetime.now(timezone.utc)-timedelta(days=8)).isoformat()},limit=1),
                    request('detail',sensor='../escape',event_id=str(uuid4()))):
        with pytest.raises(QueryFailure) as exc:
            reader.execute(invalid)
        assert exc.value.code=='INVALID'
    conn=sqlite3.connect(tmp_path/'events.db',isolation_level=None,timeout=.1)
    try:
        conn.execute('BEGIN EXCLUSIVE')
        with pytest.raises(QueryFailure) as exc:
            reader.execute(request('list',filters={},limit=1))
        assert exc.value.code=='UNAVAILABLE'
    finally:
        conn.execute('ROLLBACK')
        conn.close()
    assert reader.execute(request('list',filters={},limit=1))['items']==[]
    assert writer.health()['events']==0


def test_export_row_cap_and_private_owner_policy(tmp_path):
    writer,reader=store_fixture(tmp_path/'events.db')
    now=datetime.now(timezone.utc)
    rows=[('sensor-lab',str(uuid4()),'device-lab',now.isoformat(),now.timestamp(),now.isoformat(),
           'connect','192.0.2.12',b'{"proto":"tcp","detail":{"password":"never export"}}') for _ in range(501)]
    with sqlite3.connect(tmp_path/'events.db') as db:
        db.executemany('INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)',rows)
    data=reader.execute(request('export',filters={},limit=500))
    assert len(data['items'])==500 and data['truncated'] is True
    assert 'password' not in json.dumps(data)
    path=tmp_path/'events.db'
    path.chmod(0o644)
    with pytest.raises(QueryFailure) as exc:
        reader.execute(request('list',filters={},limit=1))
    assert exc.value.code=='UNAVAILABLE'
    path.chmod(0o600)
    assert writer.health()['events']==501


def test_event_store_only_allows_explicit_query_group_read(tmp_path,monkeypatch):
    import grp
    path=tmp_path/'events.db'
    writer,_=store_fixture(path)
    path.chmod(0o640)
    with pytest.raises(PermissionError):
        writer.health()
    monkeypatch.setenv('DYSTOPIA_QUERY_GROUP',grp.getgrgid(os.getegid()).gr_name)
    revised=EventStore(path,max_bytes=4*1024*1024)
    assert revised.health()['events']==0
    reader=QueryStore(path,owner_uid=os.geteuid(),reader_gid=os.getegid())
    assert reader.execute(request('list',filters={},limit=1))['items']==[]
    path.chmod(0o660)
    with pytest.raises(PermissionError):
        revised.health()
    with pytest.raises(QueryFailure):
        reader.execute(request('list',filters={},limit=1))


def _exchange(sock,payload):
    raw=json.dumps(payload).encode()
    sock.sendall(struct.pack('!I',len(raw))+raw)
    size=struct.unpack('!I',read_exact(sock,4))[0]
    return json.loads(read_exact(sock,size))


def test_peer_uid_denial_and_one_request_per_connection(tmp_path,monkeypatch):
    _,store=store_fixture(tmp_path/'events.db')
    from runtime import query
    # macOS lacks SO_PEERCRED; controlled stub tests the policy, not OS identity.
    monkeypatch.setattr(query,'_peer_uid',lambda conn:os.geteuid())
    a,b=socket.socketpair()
    thread=threading.Thread(target=serve_connection,args=(b,store,os.geteuid()+1))
    thread.start()
    with a:
        size=struct.unpack('!I',read_exact(a,4))[0]
        answer=json.loads(read_exact(a,size))
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert answer['error']=='DENIED' and len(answer['id'])==16
    a,b=socket.socketpair()
    thread=threading.Thread(target=serve_connection,args=(b,store,os.geteuid()))
    thread.start()
    with a:
        answer=_exchange(a,request('list',filters={},limit=1))
    thread.join(timeout=2)
    assert answer['items']==[] and answer['version']==1


def test_bridge_rejects_duplicate_fields_and_nonfinite_numbers(tmp_path,monkeypatch):
    _,store=store_fixture(tmp_path/'events.db')
    from runtime import query
    monkeypatch.setattr(query,'_peer_uid',lambda conn:os.geteuid())
    for raw in (b'{"version":1,"version":1,"operation":"list","filters":{},"limit":1}',
                b'{"version":1,"operation":"list","filters":{},"limit":NaN}',
                b'{"version":1,"operation":{},"filters":{},"limit":1}'):
        a,b=socket.socketpair()
        thread=threading.Thread(target=serve_connection,args=(b,store,os.geteuid()))
        thread.start()
        with a:
            a.sendall(struct.pack('!I',len(raw))+raw)
            size=struct.unpack('!I',read_exact(a,4))[0]
            response=json.loads(read_exact(a,size))
        thread.join(timeout=2)
        assert not thread.is_alive() and response['error']=='INVALID'


def test_control_transport_uses_unix_socket_without_storage_credentials(tmp_path,short_socket_dir,monkeypatch):
    _,store=store_fixture(tmp_path/'events.db')
    from runtime import query
    from app.services import query_client
    monkeypatch.setattr(query,'_peer_uid',lambda conn:os.geteuid())
    address=short_socket_dir/'query.sock'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(address))
        listener.listen(1)
        monkeypatch.setattr(query_client,'SOCKET_PATH',address)
        def one():
            conn,_=listener.accept()
            serve_connection(conn,store,os.geteuid())
        thread=threading.Thread(target=one)
        thread.start()
        result=query_client.query('list',filters={},limit=25)
        thread.join(timeout=2)
    assert not thread.is_alive() and result['items']==[] and result['redacted'] is True


def test_control_rejects_extra_payload_from_faulty_query_service(short_socket_dir,monkeypatch):
    from app.services import query_client
    address=short_socket_dir/'bad-query.sock'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(address))
        listener.listen(1)
        monkeypatch.setattr(query_client,'SOCKET_PATH',address)
        def one():
            conn,_=listener.accept()
            with conn:
                size=struct.unpack('!I',read_exact(conn,4))[0]
                remaining=size
                while remaining:
                    chunk=conn.recv(remaining)
                    if not chunk:
                        return
                    remaining-=len(chunk)
                blob=json.dumps({'version':1,'redacted':True,'items':[{'payload':{'password':'synthetic'}}],
                                 'total':1,'offset':0,'limit':1,'next_cursor':None,'truncated':False,
                                 'received_from':'2026-10-16T00:00:00+00:00',
                                 'received_to':'2026-10-16T01:00:00+00:00',
                                 'queried_at':'2026-10-16T01:00:00+00:00'}).encode()
                conn.sendall(struct.pack('!I',len(blob))+blob)
        thread=threading.Thread(target=one)
        thread.start()
        with pytest.raises(query_client.BridgeError) as exc:
            query_client.query('list',filters={},limit=1)
        thread.join(timeout=2)
    assert exc.value.status==503 and not thread.is_alive()


def test_synthetic_sensor_ingest_query_control_and_csv(tmp_path,short_socket_dir,monkeypatch):
    """No real HTTP server: separate ASGI planes plus real scratch Unix socket."""
    import csv
    import io
    import yaml
    from fastapi.testclient import TestClient
    from app.core.limiter import limiter
    from app.core.security import hash_password
    from app.routers import auth,admin_users
    from app.middleware import audit
    from app.main import app as control_app
    from app.services import query_client
    from runtime import query
    from runtime.identity import Registry
    from runtime.ingest import create_app
    from runtime.sensor import Spool

    monkeypatch.setattr(limiter,'enabled',False)
    monkeypatch.setattr(audit,'_log_async',lambda **kwargs:None)
    users=tmp_path/'users.yaml'
    users.write_text(yaml.safe_dump({'users':[{'username':'operator','role':'viewer','name':'Fixture',
                           'password_hash':hash_password('synthetic-integration-password-012345') }]}))
    users.chmod(0o600)
    monkeypatch.setattr(auth,'USERS_FILE',users)
    monkeypatch.setattr(admin_users,'USERS_FILE',users)
    registry=Registry(tmp_path/'identity.db')
    sensor_token=registry.rotate('sensor-lab',['device-lab'])
    writer=EventStore(tmp_path/'events.db',max_bytes=4*1024*1024)
    spool=Spool(tmp_path/'spool.db',max_bytes=4*1024*1024)
    event=synthetic_event(marker='nested synthetic password NEVER_EXPORT')
    spool.submit(event)
    with TestClient(create_app(registry,writer),base_url='https://ingest.invalid') as ingest:
        class Forward:
            def send(self,events):
                response=ingest.post('/v1/events',json={'version':1,'events':events},
                           headers={'Authorization':'Bearer '+sensor_token})
                assert response.status_code==200
        assert spool.flush_once(Forward()) is True
    assert writer.health()['events']==1
    reader=QueryStore(tmp_path/'events.db')
    monkeypatch.setattr(query,'_peer_uid',lambda conn:os.geteuid())
    address=short_socket_dir/'bridge.sock'
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(address))
        listener.listen(2)
        monkeypatch.setattr(query_client,'SOCKET_PATH',address)
        def twice():
            for _ in range(2):
                conn,_=listener.accept()
                serve_connection(conn,reader,os.geteuid())
        thread=threading.Thread(target=twice)
        thread.start()
        with TestClient(control_app) as control:
            login=control.post('/api/auth/login',json={'username':'operator',
                               'password':'synthetic-integration-password-012345'})
            assert login.status_code==200
            headers={'Authorization':'Bearer '+login.json()['access_token']}
            listing=control.get('/api/console/events?device=device-lab',headers=headers)
            export=control.get('/api/console/events.csv?device=device-lab',headers=headers)
        thread.join(timeout=3)
    assert not thread.is_alive()
    assert listing.status_code==200 and listing.json()['total']==1
    assert listing.json()['items'][0]['event_id']==event['event_id']
    assert export.status_code==200 and export.headers['x-export-truncated']=='false'
    parsed=list(csv.DictReader(io.StringIO(export.text)))
    assert len(parsed)==1 and parsed[0]['event_id']==event['event_id']
    assert 'NEVER_EXPORT' not in listing.text+export.text


def test_control_imports_no_ingest_storage_path():
    source=(Path(__file__).resolve().parents[2]/'app/routers/console.py').read_text()
    client=(Path(__file__).resolve().parents[2]/'app/services/query_client.py').read_text()
    assert 'DYSTOPIA_CONSOLE_EVENTS_DB' not in source+client
    assert 'sqlite3.connect' not in client
    assert 'runtime.storage' not in source+client
