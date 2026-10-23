"""Loopback-only stdlib dashboard. No external assets, polling or telemetry."""
import hmac
import secrets
import threading
from http.cookies import SimpleCookie
from http.server import HTTPServer, BaseHTTPRequestHandler
from . import strict_json
from .customer import Workspace, LEGACY_LIMIT
from .customer_ui import HTML, JS, CSS


class Dashboard(HTTPServer):
    allow_reuse_address = False

    def __init__(self, workspace, host='127.0.0.1', port=0):
        if host != '127.0.0.1':
            raise ValueError('Dashboard must bind strictly to 127.0.0.1')
        self.workspace = workspace
        self.bootstrap = secrets.token_urlsafe(32)
        self.session = None
        self.csrf = None
        self.pending = None
        super().__init__((host, port), Handler)
        self.origin = f'http://127.0.0.1:{self.server_port}'

    @property
    def url(self):
        return self.origin + '/#' + self.bootstrap

    def get_request(self):
        sock, addr = super().get_request()
        sock.settimeout(5)
        return sock, addr


class Handler(BaseHTTPRequestHandler):
    server_version = 'AgentReplayLocal'

    def log_message(self, *args):
        pass

    def reply(self, status, value, mime='application/json', cookie=None):
        body = strict_json.dumps(value).encode() if mime == 'application/json' else value.encode()
        self.send_response(status)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
        self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; worker-src 'none'")
        if cookie:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def boundary(self, mutation=False):
        if self.headers.get_all('Host') != [self.server.origin.removeprefix('http://')]:
            raise ValueError('Host mismatch')
        if self.headers.get('Service-Worker') or self.headers.get('Sec-Fetch-Dest') == 'serviceworker':
            raise ValueError('Service workers are disabled')
        origin = self.headers.get('Origin')
        if (mutation and self.headers.get_all('Origin') != [self.server.origin]) or (origin and origin != self.server.origin):
            raise ValueError('Origin mismatch')
        if self.headers.get('Sec-Fetch-Site') not in (None, 'same-origin', 'none'):
            raise ValueError('Cross-site request rejected')

    def authenticated(self):
        cookie = SimpleCookie()
        cookie.load(self.headers.get('Cookie', ''))
        value = cookie.get('replay_session')
        return bool(self.server.session and value and hmac.compare_digest(value.value, self.server.session)
                    and hmac.compare_digest(self.headers.get('X-Replay-CSRF', ''), self.server.csrf))

    def do_GET(self):
        try:
            self.boundary()
            assets = {'/': (HTML, 'text/html'), '/app.js': (JS, 'text/javascript'), '/style.css': (CSS, 'text/css')}
            if self.path in assets:
                return self.reply(200, *assets[self.path])
            if self.path == '/api/resume' and self.headers.get('X-Replay-Resume') == '1':
                cookie = SimpleCookie()
                cookie.load(self.headers.get('Cookie', ''))
                entry = cookie.get('replay_session')
                if self.server.session and entry and hmac.compare_digest(entry.value, self.server.session):
                    return self.reply(200, {'csrf': self.server.csrf})
            if not self.authenticated():
                return self.reply(403, {'error': 'Open the session URL printed by your local server.'})
            if self.path == '/api/state':
                return self.reply(200, self.server.workspace.public())
            return self.reply(404, {'error': 'Page not found'})
        except (ValueError, TypeError):
            self.reply(403, {'error': 'Local request security check failed'})

    def do_POST(self):
        try:
            self.boundary(mutation=True)
            if self.headers.get('Transfer-Encoding') or self.headers.get('Content-Type') != 'application/json' or len(self.headers.get_all('Content-Length', [])) != 1:
                return self.reply(400, {'error': 'A bounded JSON request is required'})
            length = int(self.headers['Content-Length'])
            limit = LEGACY_LIMIT * 6 + 4096 if self.path == '/api/analyze' else 12_004_096 if self.path == '/api/preview' else 65536
            # Upload wrapper escapes can expand bytes; content has its own exact budget.
            if not 0 < length <= limit:
                return self.reply(413, {'error': 'Upload exceeds the size limit'})
            if self.path != '/api/session' and not self.authenticated():
                return self.reply(403, {'error': 'Session or CSRF token missing'})
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete request')
            data = strict_json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError('JSON object required')
            s, w = self.server, self.server.workspace
            if self.path == '/api/session':
                if not s.bootstrap or not hmac.compare_digest(data.get('token', ''), s.bootstrap):
                    return self.reply(403, {'error': 'Session link expired or invalid; restart the local server.'})
                s.bootstrap = ''
                s.session, s.csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                return self.reply(200, {'csrf': s.csrf}, cookie=f'replay_session={s.session}; HttpOnly; SameSite=Strict; Path=/')
            if self.path == '/api/enroll':
                result = w.enroll(data['source'], data.get('mode', 'SELF_ATTESTED'))
            elif self.path == '/api/rotate':
                result = w.rotate(data['source'])
            elif self.path == '/api/revoke':
                result = w.revoke(data['key_id'], data.get('acknowledgement'))
            elif self.path in ('/api/preview', '/api/analyze'):
                content = data['data'].encode('utf-8')
                fmt = data.get('format', 'evidence')
                if len(content) > (2_000_000 if fmt == 'evidence' else LEGACY_LIMIT):
                    return self.reply(413, {'error': 'Evidence limit is 2 MB; incident limit is 32 MB'})
                if self.path == '/api/preview':
                    if fmt != 'evidence' or type(data.get('coverage', False)) is not bool:
                        raise ValueError('Only evidence-state supports attestation')
                    s.pending = (content, w.preview(content, data['source'], coverage=data.get('coverage', False)))
                    result = s.pending[1]
                elif data.get('attest'):
                    if not s.pending or content != s.pending[0]:
                        raise ValueError('Review the exact upload first')
                    result = w.analyze(content, review=s.pending[1], confirmation=data.get('confirmation'), own=data.get('own'))
                    s.pending = None
                else:
                    result = w.analyze(content, fmt)
            elif self.path == '/api/report':
                result = w.report(data['report_id'])['report']
            elif self.path == '/api/verify':
                result = w.verify(data['report_id'], historical=data.get('historical') is True)
            elif self.path == '/api/export':
                result = w.export(data['report_id'], consent=data.get('consent'))
            elif self.path == '/api/diagnostics':
                result = w.diagnostics()
            elif self.path == '/api/stop':
                self.reply(200, {'status': 'STOPPED'})
                threading.Thread(target=s.shutdown, daemon=True).start()
                return
            else:
                return self.reply(404, {'error': 'Action not found'})
            self.reply(200, result)
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError, UnicodeError, OSError):
            # Never reflect uploaded evidence, key material, paths or parser excerpts.
            self.reply(400, {'error': 'Could not complete this action. Check the format, source, exact review and key status. Existing trust fields cannot be overwritten. Workspace must remain private.'})


def serve(path):
    with Workspace(path, create=True) as workspace:
        with Dashboard(workspace) as server:
            print('Local customer dashboard (one-use session link): ' + server.url, flush=True)
            print('Private local workspace. Stop with the dashboard button or Ctrl-C.', flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
