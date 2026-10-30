"""Safe ASGI fixtures for the administrative console; no host or VM effects."""
import csv
import io
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def setup_console(tmp_path, monkeypatch):
    from app.core.security import hash_password
    from app.routers import auth, admin_users, console
    from app.services import console_svc
    from app.middleware import audit
    from app.main import app
    from app.core.limiter import limiter
    import yaml

    monkeypatch.setattr(limiter, 'enabled', False)  # isolate credentials tests from global login budget
    monkeypatch.setenv('NETPULSE_JWT_SECRET', 'synthetic-console-test-secret-0123456789')
    monkeypatch.setattr(audit, '_log_async', lambda **kwargs: None)
    monkeypatch.setattr(console_svc, 'DB_PATH', tmp_path / 'cells.db')
    users = tmp_path / 'users.yaml'
    users.write_text(yaml.safe_dump({'users': [
        {'username': role, 'role': role, 'name': role, 'password_hash': hash_password('synthetic-password-0123456789')}
        for role in ('admin', 'operator', 'viewer')]}))
    users.chmod(0o600)
    monkeypatch.setattr(auth, 'USERS_FILE', users)
    monkeypatch.setattr(admin_users, 'USERS_FILE', users)
    from app.services import query_client
    monkeypatch.setattr(query_client, 'SOCKET_PATH', None)
    with TestClient(app) as client:
        tokens = {}
        for role in ('admin', 'operator', 'viewer'):
            r = client.post('/api/auth/login', json={'username': role, 'password': 'synthetic-password-0123456789'})
            assert r.status_code == 200
            tokens[role] = {'Authorization': 'Bearer ' + r.json()['access_token']}
        yield client, tokens, tmp_path, console


def local_query(store):
    from app.services.query_client import BridgeError, ERROR_CODES
    from runtime.query import QueryFailure
    def call(operation, **params):
        try:
            return store.execute({'version': 1, 'operation': operation, **params})
        except QueryFailure as exc:
            raise BridgeError(ERROR_CODES.get(exc.code, 503), '1111111111111111') from None
    return call


def draft(**changes):
    return {'name': 'Celda laboratorio', 'purpose': 'Evaluar telemetría sintética',
            'profile': 'server', 'segment': 'lab-net', 'address': '192.0.2.10',
            'sensor_id': 'sensor-lab', 'device_id': 'device-lab', 'cpu': 1, 'memory_mb': 512, 'allowed_ports': [22], **changes}


def test_draft_validation_revision_and_per_role_denial(setup_console):
    client, tokens, path, _ = setup_console
    url = '/api/console/cells/lab-cell'
    assert client.get('/api/console/cells').status_code == 401
    assert client.post(url, json=draft(), headers=tokens['viewer']).status_code == 403
    assert client.post(url, json=draft(), headers=tokens['operator']).status_code == 403
    created = client.post(url, json=draft(), headers=tokens['admin'])
    assert created.status_code == 201
    assert created.json()['revision'] == 1
    assert created.json()['operational_state'] == 'draft'
    assert created.json()['verification']['state'] == 'unavailable'
    assert (path/'cells.db').stat().st_mode & 0o077 == 0
    assert client.post(url, json=draft(), headers=tokens['admin']).status_code == 409
    assert client.post(url+'/validate', json={'revision':1}, headers=tokens['viewer']).status_code == 403
    result = client.post(url+'/validate', json={'revision':1}, headers=tokens['operator'])
    assert result.status_code == 200
    assert result.json()['state'] == 'complete'
    assert result.json()['activation_allowed'] is False
    assert result.json()['scope'] == 'declarative_only'
    assert client.post(url+'/activate', headers=tokens['viewer']).status_code == 403
    assert client.post(url+'/prepare', headers=tokens['operator']).status_code == 403
    assert client.post(url+'/activate', headers=tokens['admin']).status_code == 409
    assert client.post(url+'/prepare', headers=tokens['admin']).status_code == 409
    updated = client.put(url+'?revision=1', json=draft(purpose='Actualizado'), headers=tokens['admin'])
    assert updated.status_code == 200
    assert updated.json()['revision'] == 2
    assert updated.json()['validation'] is None
    assert client.put(url+'?revision=1', json=draft(), headers=tokens['admin']).status_code == 409
    assert client.post(url+'/validate', json={'revision':1}, headers=tokens['operator']).status_code == 409
    history = client.get(url+'/history', headers=tokens['viewer']).json()
    assert [item['action'] for item in history] == ['update','validate_config','create']
    assert all(item['actor'] in {'admin','operator'} for item in history)


def test_event_api_rejects_generic_api_key_principal():
    from fastapi import HTTPException
    from starlette.requests import Request
    from app.routers.console import _human_session
    request=Request({'type':'http','method':'GET','path':'/api/console/events','headers':[],
                     'client':('127.0.0.1',0),'server':('127.0.0.1',0),'scheme':'http'})
    request.state.user={'sub':'apikey:automation','role':'viewer','api_key_id':'synthetic-id'}
    with pytest.raises(HTTPException) as exc:
        _human_session(request)
    assert exc.value.status_code==403


def test_installer_environment_cannot_be_overridden_by_ui_label(setup_console, monkeypatch):
    client,tokens,_,_=setup_console
    monkeypatch.setenv('NETPULSE_ENV','production')
    monkeypatch.setenv('DYSTOPIA_ENVIRONMENT','laboratory')
    response=client.get('/api/console/capabilities', headers=tokens['viewer'])
    assert response.json()['environment'] == 'production'


def test_missing_state_directory_is_unavailable_not_empty(setup_console, monkeypatch):
    client,tokens,path,_ = setup_console
    from app.services import console_svc
    monkeypatch.setattr(console_svc, 'DB_PATH', path/'not-provisioned'/'cells.db')
    assert client.get('/api/console/cells', headers=tokens['viewer']).status_code == 503
    assert not (path/'not-provisioned').exists()


def test_draft_invalid_fields_do_not_write(setup_console):
    client,tokens,path,_ = setup_console
    for changes in ({'address':'192.0.2.999'}, {'profile':'payload'}, {'allowed_ports':[22,22]}, {'sensor_id':'../escape'}, {'name':'   '}):
        assert client.post('/api/console/cells/bad', json=draft(**changes), headers=tokens['admin']).status_code == 422
    assert not (path/'cells.db').exists()


def test_event_contract_fail_closed_filters_order_export_and_formula_safety(setup_console):
    client,tokens,path,console = setup_console
    url = '/api/console/events'
    unavailable=client.get(url, headers=tokens['viewer'])
    assert unavailable.status_code == 503 and len(unavailable.headers['x-query-error-id']) == 16
    events = path/'ingest.db'
    from runtime.storage import EventStore
    store = EventStore(events, max_bytes=4*1024*1024)
    from uuid import uuid4
    payload = [{'event_id':str(uuid4()), 'device_id':'cell-one', 'observed_at':'2026-10-16T10:00:00+00:00',
                'type':'connect','src_ip':'192.0.2.9','proto':'tcp','detail':{'password':'MUST_NOT_LEAK'}}]
    store.ingest('sensor-A', payload)
    # Synthetic hostile legacy row: v1 ingest would reject a non-IP source.
    with sqlite3.connect(events) as db:
        db.execute("UPDATE events SET source='=1+1' WHERE sensor='sensor-A'")
    monkey = pytest.MonkeyPatch()
    from runtime.query import QueryStore
    from app.services import query_client
    query_store=QueryStore(events)
    monkey.setattr(query_client, 'query', local_query(query_store))
    try:
        r = client.get(url+'?limit=1&sensor=sensor-A', headers=tokens['viewer'])
        assert r.status_code == 200
        assert r.json()['total'] == 1
        assert r.json()['items'][0]['source'] == '<invalid>'
        assert client.get(url+'?device=not-this-one', headers=tokens['viewer']).json()['total'] == 0
        assert client.get(url+'?cursor=invalid', headers=tokens['viewer']).status_code == 422
        activity = client.get('/api/console/activity?minutes=30', headers=tokens['operator'])
        assert activity.status_code == 200
        assert activity.json()['unit'] == 'events/minute'
        assert sum(x['count'] for x in activity.json()['buckets']) == 1
        assert 'password' not in json.dumps(r.json())
        event_id = r.json()['items'][0]['event_id']
        detail = client.get(f'/api/console/events/sensor-A/{event_id}', headers=tokens['viewer'])
        assert detail.status_code == 200 and detail.json()['redacted'] is True
        assert 'password' not in detail.text and 'payload' not in detail.json()['event']
        assert client.get('/api/console/events/sensor-A/not-a-uuid', headers=tokens['viewer']).status_code == 422
        invalid=client.get(url+'?limit=101', headers=tokens['viewer'])
        assert invalid.status_code == 422 and len(invalid.headers['x-query-error-id']) == 16
        assert client.get(url+'?sensor=missing', headers=tokens['viewer']).json()['total'] == 0
        csv_response = client.get('/api/console/events.csv?sensor=sensor-A', headers=tokens['viewer'])
        assert csv_response.status_code == 200
        assert csv_response.headers['x-export-truncated'] == 'false'
        assert csv_response.headers['x-export-rows'] == '1'
        rows = list(csv.reader(io.StringIO(csv_response.text)))
        assert rows[1][6] == '<invalid>'
        assert 'password' not in csv_response.text
        assert client.get('/api/console/capabilities', headers=tokens['viewer']).json()['can_edit_drafts'] is False
        assert client.get('/api/console/events?from_time=2026-10-16T12:00:00', headers=tokens['viewer']).status_code == 422
        assert client.get('/api/console/events.csv?sensor=missing', headers=tokens['viewer']).text.strip() == ','.join(rows[0])
        link = path/'linked.db'
        link.symlink_to(events)
        query_store.path = link
        assert client.get(url, headers=tokens['viewer']).status_code == 503
    finally:
        monkey.undo()


def test_user_creation_requires_admin_and_strong_password(setup_console):
    client,tokens,_,_ = setup_console
    body={'username':'newviewer','name':'Test Viewer','role':'viewer','password':'synthetic-new-password-0123456789'}
    assert client.post('/api/admin/users', json=body, headers=tokens['viewer']).status_code == 403
    assert client.post('/api/admin/users', json={**body,'password':'weak1234'}, headers=tokens['admin']).status_code == 422
    assert client.post('/api/admin/users', json={**body,'password':'á'*40}, headers=tokens['admin']).status_code == 422
    assert client.post('/api/admin/users', json={**body,'username':'../bad'}, headers=tokens['admin']).status_code == 422
    created=client.post('/api/admin/users', json=body, headers=tokens['admin'])
    assert created.status_code == 201
    assert created.json()['role'] == 'viewer'
    assert 'password' not in created.text


def test_deleted_demo_user_token_is_rejected(setup_console):
    client,tokens,_,_=setup_console
    old=tokens['viewer']
    assert client.delete('/api/admin/users/viewer',headers=tokens['admin']).status_code==204
    assert client.get('/api/console/events',headers=old).status_code==401


def test_password_change_revokes_existing_user_token(setup_console):
    client,tokens,_,_=setup_console
    old=tokens['viewer']
    changed=client.put('/api/admin/users/viewer',
                       json={'password':'different-synthetic-password-02'}, headers=tokens['admin'])
    assert changed.status_code==200
    assert client.get('/api/console/events', headers=old).status_code==401
    assert client.post('/api/auth/login',json={'username':'viewer','password':'synthetic-password-0123456789'}).status_code==401
    assert client.post('/api/auth/login',json={'username':'viewer','password':'different-synthetic-password-02'}).status_code==200


def test_csv_export_advertises_truncation(setup_console, monkeypatch):
    client,tokens,path,console=setup_console
    from datetime import datetime, timezone
    from uuid import uuid4
    from runtime.storage import EventStore
    dbpath=path/'events.db'
    EventStore(dbpath,max_bytes=4*1024*1024)
    now=datetime.now(timezone.utc)
    rows=[('sensor-lab',str(uuid4()),'device-lab',now.isoformat(),now.timestamp(),now.isoformat(),
           'connect','192.0.2.10',b'{"proto":"tcp"}') for _ in range(501)]
    with sqlite3.connect(dbpath) as db:
        db.executemany('INSERT INTO events(sensor,event_id,device,received_at,received_epoch,observed_at,kind,source,payload) VALUES(?,?,?,?,?,?,?,?,?)', rows)
    from runtime.query import QueryStore
    from app.services import query_client
    monkeypatch.setattr(query_client, 'query', local_query(QueryStore(dbpath)))
    result=client.get('/api/console/events.csv?sensor=sensor-lab', headers=tokens['viewer'])
    assert result.status_code == 200
    assert result.headers['x-export-truncated'] == 'true'
    assert len(list(csv.reader(io.StringIO(result.text)))) == 501


def test_csv_formula_prefixes_and_console_escapes_hostile_metadata():
    from app.routers.console import _csv_safe
    from pathlib import Path
    assert _csv_safe('   =1+2').startswith("'")
    assert _csv_safe('\t@external').startswith("'")
    assert _csv_safe('normal') == 'normal'
    js = (Path(__file__).resolve().parents[2] / 'app/static/console.js').read_text()
    assert "const esc = value =>" in js
    assert "'&':'&amp;'" in js and "'<':'&lt;'" in js


def test_login_handler_captures_form_before_async_reset():
    js = (Path(__file__).resolve().parents[2] / 'app/static/console.js').read_text()
    assert "const form=event.currentTarget" in js
    assert "new FormData(form)" in js
    assert "form.reset()" in js


def test_login_budget_ignores_untrusted_forwarded_headers():
    from starlette.requests import Request
    from app.core.limiter import client_key
    request = Request({'type': 'http', 'method': 'POST', 'path': '/api/auth/login',
                       'headers': [(b'x-forwarded-for', b'203.0.113.1'), (b'x-real-ip', b'198.51.100.1')],
                       'client': ('127.0.0.1', 50123), 'server': ('127.0.0.1', 8082), 'scheme': 'http'})
    assert client_key(request) == '127.0.0.1'


def test_admin_audit_metadata_only_and_per_role(setup_console, monkeypatch):
    client,tokens,path,console=setup_console
    audit_dir=path/'audit'
    audit_dir.mkdir()
    file=audit_dir/'audit.db'
    with sqlite3.connect(file) as db:
        db.execute('CREATE TABLE audit (id INTEGER PRIMARY KEY,ts TEXT,action TEXT,username TEXT,method TEXT,path TEXT,response_status INTEGER,details TEXT,ip_address TEXT)')
        db.execute("INSERT INTO audit VALUES(1,'2026-10-16T12:00:00Z','api_post','admin','POST','/api/console/cells/{cell_id}',201,'SECRET','192.0.2.1')")
    file.chmod(0o600)
    monkeypatch.setattr(console, 'STATE_DIR', path)
    assert client.get('/api/console/audit', headers=tokens['viewer']).status_code == 403
    result=client.get('/api/console/audit', headers=tokens['admin'])
    assert result.status_code == 200
    assert result.json()['total'] == 1
    assert 'SECRET' not in result.text and '192.0.2.1' not in result.text
