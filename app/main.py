import base64
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import tempfile
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator

from .db import initialize, database, digest, hash_password, verify_password, audit
from .core import compile_config, revision, eligible, status, profiles


@asynccontextmanager
async def lifespan(app):
    initialize()
    yield


app = FastAPI(title='Donino Panel', version='0.1.0', lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
STATIC = Path(__file__).parent / 'static'
app.mount('/static', StaticFiles(directory=STATIC), name='static')


@app.middleware('http')
async def security_headers(request, call_next):
    # Cookie authentication mutations require a header unavailable to HTML forms.
    # No CORS is enabled. Also reject cross-origin requests with an Origin header.
    if request.method in ('POST', 'PATCH', 'DELETE', 'PUT'):
        if request.headers.get('origin') and request.headers['origin'] != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail': 'Cross-origin request rejected'}, status_code=403)
        if not request.url.path.startswith('/api/agent/') and request.headers.get('x-donino') != '1':
            return JSONResponse({'detail': 'X-Donino header required'}, status_code=403)
    # Bound the actual body, including requests without Content-Length.
    if request.method in ('POST', 'PATCH', 'PUT'):
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 2_000_000:
                return JSONResponse({'detail': 'Request too large'}, status_code=413)
        request._body = bytes(body)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response


@app.exception_handler(sqlite3.IntegrityError)
async def conflict(request, exc):
    return JSONResponse({'detail': 'نام یا پورت تکراری است، یا رکورد مرتبط وجود ندارد.'}, status_code=409)


def admin(request: Request):
    token = request.cookies.get('donino_session', '')
    with database() as db:
        row = db.execute('SELECT a.username,a.role FROM sessions s JOIN admins a USING(username) '
                         'WHERE s.token=? AND s.expires>?', (digest(token), int(time.time()))).fetchone()
    if not row:
        raise HTTPException(401, 'ورود لازم است')
    return dict(row)


def writer(account=Depends(admin)):
    if account['role'] not in ('owner', 'operator'):
        raise HTTPException(403, 'دسترسی نوشتن ندارید')
    return account


def owner(account=Depends(admin)):
    if account['role'] != 'owner':
        raise HTTPException(403, 'دسترسی مالک لازم است')
    return account


def node_auth(request: Request):
    auth = request.headers.get('authorization', '')
    if not auth.startswith('Bearer '):
        raise HTTPException(401, 'Node token required')
    with database() as db:
        node = db.execute('SELECT * FROM nodes WHERE token=? AND enabled=1', (digest(auth[7:]),)).fetchone()
    if not node:
        raise HTTPException(401, 'Invalid node token')
    return dict(node)


def one(db, table, record_id):
    # Table names are internal constants only.
    row = db.execute(f'SELECT * FROM {table} WHERE id=?', (record_id,)).fetchone()
    if not row:
        raise HTTPException(404, 'رکورد پیدا نشد')
    return row


def public_user(row, include_secret=False):
    value = dict(row)
    value.pop('credential', None)
    value['status'] = status(value)
    if not include_secret:
        value.pop('token', None)
    return value


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class UserInput(BaseModel):
    name: str = Field(min_length=1, max_length=80, pattern=r'^[\w .@+-]+$')
    enabled: bool = True
    quota: int = Field(default=0, ge=0, le=9_000_000_000_000_000)
    expires: int | None = Field(default=None, gt=0, le=32_503_680_000)


class NodeInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)

    @field_validator('host')
    @classmethod
    def valid_host(cls, value):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if not re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', value):
                raise ValueError('Host must be an IP or domain, without scheme or port')
        return value


class InboundInput(BaseModel):
    node_id: str
    name: str = Field(min_length=1, max_length=80)
    protocol: str = Field(pattern=r'^(vless|vmess|trojan)$')
    port: int = Field(ge=1, le=65535)
    sni: str = Field(min_length=1, max_length=253, pattern=r'^[A-Za-z0-9.-]+$')
    target: str = Field(default='www.microsoft.com:443', max_length=260, pattern=r'^[A-Za-z0-9.-]+:[0-9]{1,5}$')
    path: str = Field(default='/donino', max_length=200, pattern=r'^/[^\s?#]*$')
    cert_file: str = Field(default='', max_length=500)
    key_file: str = Field(default='', max_length=500)

    @model_validator(mode='after')
    def valid_settings(self):
        if self.port == 10085:
            raise ValueError('10085 is reserved for local statistics')
        if self.protocol != 'vless' and (not self.cert_file.startswith('/') or not self.key_file.startswith('/')):
            raise ValueError('TLS needs absolute certificate and key paths on the node')
        if not 1 <= int(self.target.rsplit(':', 1)[1]) <= 65535:
            raise ValueError('Invalid REALITY target port')
        return self


class Usage(BaseModel):
    user_id: str
    up: int = Field(ge=0, le=9_000_000_000_000_000)
    down: int = Field(ge=0, le=9_000_000_000_000_000)


class Heartbeat(BaseModel):
    epoch: str = Field(min_length=1, max_length=64)
    applied_revision: str = Field(default='', max_length=64)
    error: str = Field(default='', max_length=500)
    usage: list[Usage] = Field(default_factory=list, max_length=10000)

    @model_validator(mode='after')
    def unique_users(self):
        if len({u.user_id for u in self.usage}) != len(self.usage):
            raise ValueError('Duplicate usage user')
        return self


@app.get('/')
def index():
    return FileResponse(STATIC / 'index.html')


@app.get('/healthz')
def health():
    return {'status': 'ok', 'version': '0.1.0'}


@app.post('/api/login')
def login(body: Login, request: Request, response: Response):
    address = request.client.host if request.client else 'unknown'
    now = int(time.time())
    with database() as db:
        attempts = db.execute('SELECT * FROM login_attempts WHERE address=?', (address,)).fetchone()
        if attempts and attempts['until'] > now and attempts['attempts'] >= 10:
            raise HTTPException(429, 'تلاش‌های زیاد؛ ۱۵ دقیقه دیگر دوباره امتحان کنید')
        row = db.execute('SELECT * FROM admins WHERE username=?', (body.username,)).fetchone()
        # Use a fixed dummy hash to avoid a fast unknown-user path.
        dummy = 'donino-dummy:' + '0' * 64
        valid = verify_password(body.password, row['password'] if row else dummy)
        if not row or not valid:
            count = attempts['attempts'] + 1 if attempts and attempts['until'] > now else 1
            db.execute('INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)', (address, count, now + 900))
            # Commit failed attempts before returning an HTTP error.
            return JSONResponse({'detail': 'نام کاربری یا رمز عبور اشتباه است'}, status_code=401)
        db.execute('DELETE FROM login_attempts WHERE address=?', (address,))
        db.execute('DELETE FROM sessions WHERE expires<=?', (now,))
        token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO sessions VALUES(?,?,?)', (digest(token), row['username'], now + 43200))
        audit(db, row['username'], 'login')
    response.set_cookie('donino_session', token, httponly=True, samesite='strict', max_age=43200,
                        secure=os.environ.get('DONINO_SECURE_COOKIE', 'true').lower() != 'false')
    return {'username': row['username'], 'role': row['role']}


@app.post('/api/logout')
def logout(request: Request, response: Response):
    with database() as db:
        db.execute('DELETE FROM sessions WHERE token=?', (digest(request.cookies.get('donino_session', '')),))
    response.delete_cookie('donino_session')
    return {'ok': True}


@app.get('/api/me')
def me(account=Depends(admin)):
    return account


@app.get('/api/openapi.json')
def schema(account=Depends(admin)):
    return app.openapi()


@app.get('/api/overview')
def overview(account=Depends(admin)):
    with database() as db:
        users = [public_user(r) for r in db.execute('SELECT * FROM users')]
        nodes = list(db.execute('SELECT last_seen,enabled,error FROM nodes'))
        online = sum(bool(n['enabled'] and n['last_seen'] and n['last_seen'] > time.time() - 30 and not n['error']) for n in nodes)
        return {'users': len(users), 'active': sum(u['status'] == 'active' for u in users),
                'used': sum(u['used'] for u in users), 'nodes': len(nodes), 'online_nodes': online,
                'inbounds': db.execute('SELECT COUNT(*) FROM inbounds WHERE enabled=1').fetchone()[0]}


@app.get('/api/users')
def list_users(account=Depends(admin)):
    with database() as db:
        return [public_user(r) for r in db.execute('SELECT * FROM users ORDER BY created DESC LIMIT 1000')]


@app.post('/api/users', status_code=201)
def add_user(body: UserInput, account=Depends(writer)):
    uid = str(uuid.uuid4())
    with database() as db:
        db.execute('INSERT INTO users(id,credential,name,enabled,quota,expires,token,created) VALUES(?,?,?,?,?,?,?,?)',
                   (uid, str(uuid.uuid4()), body.name, body.enabled, body.quota, body.expires, secrets.token_urlsafe(32), int(time.time())))
        audit(db, account['username'], 'user.create', uid)
        return public_user(one(db, 'users', uid))


@app.put('/api/users/{uid}')
def update_user(uid: str, body: UserInput, account=Depends(writer)):
    with database() as db:
        one(db, 'users', uid)
        db.execute('UPDATE users SET name=?,enabled=?,quota=?,expires=? WHERE id=?',
                   (body.name, body.enabled, body.quota, body.expires, uid))
        audit(db, account['username'], 'user.update', uid)
        return public_user(one(db, 'users', uid))


@app.delete('/api/users/{uid}')
def delete_user(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, 'users', uid)
        db.execute('DELETE FROM users WHERE id=?', (uid,))
        audit(db, account['username'], 'user.delete', uid)
    return {'ok': True}


@app.post('/api/users/{uid}/reset-traffic')
def reset_traffic(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, 'users', uid)
        # Keep cumulative high-water marks to avoid billing old bytes again.
        db.execute('UPDATE users SET used=0 WHERE id=?', (uid,))
        audit(db, account['username'], 'user.reset-traffic', uid)
    return {'ok': True}


@app.post('/api/users/{uid}/rotate-subscription')
def rotate_subscription(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, 'users', uid)
        db.execute('UPDATE users SET token=? WHERE id=?', (secrets.token_urlsafe(32), uid))
        audit(db, account['username'], 'user.rotate-subscription', uid)
    return {'ok': True}


@app.get('/api/users/{uid}/subscription')
def subscription_info(uid: str, request: Request, account=Depends(writer)):
    with database() as db:
        row = one(db, 'users', uid)
        base = os.environ.get('DONINO_PUBLIC_URL', str(request.base_url).rstrip('/')).rstrip('/')
        return {'url': base + '/sub/' + row['token']}


@app.post('/api/users/{uid}/rotate-credentials')
def rotate_credentials(uid: str, account=Depends(writer)):
    with database() as db:
        one(db, 'users', uid)
        db.execute('UPDATE users SET credential=?,token=? WHERE id=?',
                   (str(uuid.uuid4()), secrets.token_urlsafe(32), uid))
        audit(db, account['username'], 'user.rotate-credentials', uid)
    return {'ok': True}


@app.get('/api/nodes')
def list_nodes(account=Depends(admin)):
    with database() as db:
        result = []
        for row in db.execute('SELECT * FROM nodes'):
            n = dict(row)
            n.pop('token')
            n['online'] = bool(n['enabled'] and n['last_seen'] and n['last_seen'] > time.time() - 30 and not n['error'])
            result.append(n)
        return result


@app.post('/api/nodes', status_code=201)
def add_node(body: NodeInput, account=Depends(owner)):
    token, nid = secrets.token_urlsafe(48), str(uuid.uuid4())
    with database() as db:
        db.execute('INSERT INTO nodes(id,name,host,token) VALUES(?,?,?,?)', (nid, body.name, body.host, digest(token)))
        audit(db, account['username'], 'node.create', nid)
    return {'id': nid, 'token': token}


@app.delete('/api/nodes/{nid}')
def delete_node(nid: str, account=Depends(owner)):
    with database() as db:
        one(db, 'nodes', nid)
        db.execute('DELETE FROM nodes WHERE id=?', (nid,))
        audit(db, account['username'], 'node.delete', nid)
    return {'ok': True}


@app.post('/api/nodes/{nid}/rotate-token')
def rotate_node(nid: str, account=Depends(owner)):
    token = secrets.token_urlsafe(48)
    with database() as db:
        one(db, 'nodes', nid)
        db.execute('UPDATE nodes SET token=? WHERE id=?', (digest(token), nid))
        audit(db, account['username'], 'node.rotate-token', nid)
    return {'token': token}


@app.get('/api/inbounds')
def list_inbounds(account=Depends(admin)):
    with database() as db:
        result = []
        for row in db.execute('SELECT i.*,n.name node_name FROM inbounds i JOIN nodes n ON n.id=i.node_id'):
            value = dict(row)
            s = json.loads(value['settings'])
            s.pop('private_key', None)
            value['settings'] = s
            result.append(value)
        return result


@app.post('/api/inbounds', status_code=201)
def add_inbound(body: InboundInput, account=Depends(owner)):
    settings = body.model_dump(exclude={'node_id', 'name', 'protocol', 'port'})
    if body.protocol == 'vless':
        private = X25519PrivateKey.generate()
        enc = lambda value: base64.urlsafe_b64encode(value).decode().rstrip('=')
        settings.update({'private_key': enc(private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())),
                         'public_key': enc(private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
                         'short_id': secrets.token_hex(8)})
    iid = str(uuid.uuid4())
    with database() as db:
        one(db, 'nodes', body.node_id)
        db.execute('INSERT INTO inbounds(id,node_id,name,protocol,port,settings) VALUES(?,?,?,?,?,?)',
                   (iid, body.node_id, body.name, body.protocol, body.port, json.dumps(settings)))
        audit(db, account['username'], 'inbound.create', iid)
    return {'id': iid}


@app.delete('/api/inbounds/{iid}')
def delete_inbound(iid: str, account=Depends(owner)):
    with database() as db:
        one(db, 'inbounds', iid)
        db.execute('DELETE FROM inbounds WHERE id=?', (iid,))
        audit(db, account['username'], 'inbound.delete', iid)
    return {'ok': True}


@app.get('/api/agent/config')
def agent_config(node=Depends(node_auth)):
    with database() as db:
        config = compile_config(list(db.execute('SELECT * FROM inbounds WHERE node_id=? ORDER BY id', (node['id'],))),
                                list(db.execute('SELECT * FROM users ORDER BY id')))
    return {'revision': revision(config), 'config': config}


@app.post('/api/agent/heartbeat')
def heartbeat(body: Heartbeat, node=Depends(node_auth)):
    with database() as db:
        for sample in body.usage:
            if not db.execute('SELECT 1 FROM users WHERE id=?', (sample.user_id,)).fetchone():
                continue
            old = db.execute('SELECT up,down FROM counters WHERE node_id=? AND epoch=? AND user_id=?',
                             (node['id'], body.epoch, sample.user_id)).fetchone()
            up, down = max(sample.up, old['up'] if old else 0), max(sample.down, old['down'] if old else 0)
            delta = up + down - (old['up'] + old['down'] if old else 0)
            db.execute('UPDATE users SET used=used+? WHERE id=?', (delta, sample.user_id))
            db.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?,?,?)',
                       (node['id'], body.epoch, sample.user_id, up, down))
        db.execute('UPDATE nodes SET last_seen=?,applied_revision=?,error=? WHERE id=?',
                   (int(time.time()), body.applied_revision, body.error, node['id']))
    return {'ok': True}


@app.get('/api/audit')
def list_audit(account=Depends(owner)):
    with database() as db:
        return [dict(r) for r in db.execute('SELECT * FROM audit ORDER BY id DESC LIMIT 200')]


@app.get('/api/backup')
def backup(account=Depends(owner)):
    # Back up without holding a write transaction on the source connection.
    from .db import db_path
    with tempfile.TemporaryDirectory() as folder:
        filename = Path(folder) / 'backup.db'
        source = sqlite3.connect(db_path())
        target = sqlite3.connect(filename)
        try:
            source.backup(target)
        finally:
            source.close()
            target.close()
        data = filename.read_bytes()
    with database() as db:
        audit(db, account['username'], 'backup.download')
    return Response(data, media_type='application/vnd.sqlite3',
                    headers={'Content-Disposition': 'attachment; filename=donino-backup.db'})


@app.get('/sub/{token}')
def subscription(token: str, format: str = 'base64'):
    if format not in ('base64', 'raw', 'clash'):
        raise HTTPException(400, 'Formats: base64, raw, clash')
    with database() as db:
        user = db.execute('SELECT * FROM users WHERE token=?', (token,)).fetchone()
        if not user or not eligible(user):
            raise HTTPException(404, 'Subscription unavailable')
        inbounds = list(db.execute('SELECT i.*,n.host,n.name node_name,n.enabled node_enabled '
                                  'FROM inbounds i JOIN nodes n ON n.id=i.node_id ORDER BY i.id'))
        links, clash = profiles(user, inbounds)
        info = f'upload=0; download={user["used"]}; total={user["quota"]}; expire={user["expires"] or 0}'
    headers = {'Subscription-Userinfo': info, 'Profile-Update-Interval': '6',
               'Content-Disposition': 'inline; filename=donino-subscription.txt'}
    if format == 'clash':
        return JSONResponse(clash, headers=headers)
    content = '\n'.join(links)
    if format == 'base64':
        content = base64.b64encode(content.encode()).decode()
    return Response(content, media_type='text/plain', headers=headers)
