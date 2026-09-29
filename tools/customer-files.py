# /// script
# requires-python = ">=3.10"
# dependencies = ["PyJWT[crypto]>=2.10,<3", "keyring>=25,<26"]
# ///
"""Current-user OAuth/device-password and WebDAV CLI. Never prints credentials."""
import argparse
import base64
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import urllib.error
import urllib.parse as url
import urllib.request as http
import xml.etree.ElementTree as ET

CLIENT = 'cells-client'
CALLBACK = 'http://localhost:3000/servers/callback'


class NoRedirect(http.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(method, address, headers=None, data=None):
    origin = url.urlsplit(address)[:2]
    for _ in range(5):
        try:
            with http.build_opener(NoRedirect).open(http.Request(address, data=data, headers=headers or {}, method=method), timeout=90) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            target = url.urljoin(address, e.headers.get('Location', ''))
            parsed = url.urlsplit(target)
            if e.code in (307, 308) and target != address and parsed[:2] == origin and not parsed.username and parsed.path.startswith('/dav/') and url.urlsplit(address).path.startswith('/dav/'):
                address = target
                continue
            raise RuntimeError(f'HTTP {e.code} ({method}); response body omitted') from None
    raise RuntimeError('Redirect limit reached')


def json_request(method, address, data=None, headers=None):
    h = {'Content-Type': 'application/json', **(headers or {})}
    _, raw = request(method, address, h, json.dumps(data).encode() if data is not None else None)
    return json.loads(raw)


def server(value):
    parsed = url.urlsplit(value)
    if parsed.scheme != 'https' or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
        raise ValueError('--server must be an HTTPS origin, without a path or credentials')
    return value.rstrip('/')


def credential(args, value=None):
    if args.credential_file:
        path = Path(args.credential_file).expanduser()
        if value is None:
            if os.name != 'nt' and path.stat().st_mode & 0o077:
                raise RuntimeError('Credential file must have mode 0600')
            result = json.loads(path.read_text())
        else:
            if os.name == 'nt':
                raise RuntimeError('On Windows use Credential Manager (omit --credential-file)')
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            # Do not overwrite or follow an existing credential file.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump(value, stream)
            return
    else:
        import keyring
        key = 'customer-files:' + args.server
        if value is not None:
            if keyring.get_password(key, args.profile):
                raise RuntimeError('Profile already exists; use another --profile or logout first')
            keyring.set_password(key, args.profile, json.dumps(value))
            return
        raw = keyring.get_password(key, args.profile)
        if not raw:
            raise RuntimeError('No credential for this server/profile; run login or import-password')
        result = json.loads(raw)
    if result.get('server') != args.server:
        raise RuntimeError('Credential belongs to a different server')
    return result


def forget(args):
    if args.credential_file:
        Path(args.credential_file).expanduser().unlink()
    else:
        import keyring
        keyring.delete_password('customer-files:' + args.server, args.profile)


def device(args, access, kind, **fields):
    return json_request('POST', args.server + '/a/frontend/session',
                        {'AuthInfo': {'type': 'device_password_' + kind, 'access_token': access, **fields}})


def login(args):
    import jwt
    # Preflight credential storage before the user authorizes or a token is minted.
    if args.credential_file:
        if os.name == 'nt' or Path(args.credential_file).expanduser().exists():
            raise RuntimeError('Use a new credential file on Unix, or OS keyring on Windows')
    else:
        import keyring
        if keyring.get_keyring().priority <= 0:
            raise RuntimeError('No OS keyring; on a managed Unix host use an explicit --credential-file')
        if keyring.get_password('customer-files:' + args.server, args.profile):
            raise RuntimeError('Profile already exists; use another --profile or logout first')
    discovery = json_request('GET', args.server + '/oidc/.well-known/openid-configuration')
    for key in ('authorization_endpoint', 'token_endpoint', 'jwks_uri', 'issuer'):
        if url.urlsplit(discovery[key])[:2] != url.urlsplit(args.server)[:2]:
            raise RuntimeError('Discovery endpoint is not on the selected server')
    jwks = jwt.PyJWKSet.from_dict(json_request('GET', discovery['jwks_uri']))
    state, nonce, verifier = (secrets.token_urlsafe(48) for _ in range(3))
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
    params = {'client_id': CLIENT, 'redirect_uri': CALLBACK, 'response_type': 'code',
              'scope': 'openid profile email pydio', 'state': state, 'nonce': nonce,
              'code_challenge': challenge, 'code_challenge_method': 'S256'}
    print('Open this URL in your logged-in browser:\n' + discovery['authorization_endpoint'] + '?' + url.urlencode(params), flush=True)
    print('Keep this process running. After authorization, localhost may not respond.\nPaste its complete callback URL below (hidden input).', flush=True)
    callback = url.urlsplit(getpass.getpass('Callback URL: ').strip())
    query = url.parse_qs(callback.query, strict_parsing=True)
    if url.urlunsplit((callback.scheme, callback.netloc, callback.path, '', '')) != CALLBACK or query.get('state') != [state] or len(query.get('code', [])) != 1:
        raise RuntimeError('Callback origin/path/state/code mismatch; restart login')
    fields = {'client_id': CLIENT, 'grant_type': 'authorization_code', 'code': query['code'][0], 'redirect_uri': CALLBACK, 'code_verifier': verifier}
    _, raw = request('POST', discovery['token_endpoint'], {'Content-Type': 'application/x-www-form-urlencoded'}, url.urlencode(fields).encode())
    tokens = json.loads(raw)
    kid = jwt.get_unverified_header(tokens['id_token'])['kid']
    claims = jwt.decode(tokens['id_token'], jwks[kid].key, algorithms=['RS256'], audience=CLIENT,
                        issuer=discovery['issuer'], options={'require': ['exp', 'iss', 'sub', 'aud', 'nonce']})
    if claims['nonce'] != nonce:
        raise RuntimeError('OIDC nonce mismatch')
    # Use OAuth access_token, not id_token, to request a current-user credential.
    minted = device(args, tokens['access_token'], 'create', label=args.device_name)
    info = minted['TriggerInfo']
    value = {'server': args.server, 'username': info['username'], 'password': minted['Token']['AccessToken'], 'id': info['id']}
    try:
        credential(args, value)
    except Exception:
        device(args, tokens['access_token'], 'revoke', id=info['id'])
        raise
    print('OAuth verified; current-user device password saved. No secret printed.')


def dav_address(base, workspace, remote):
    parts = remote.split('/')
    if remote.startswith('/') or any(p in ('.', '..') for p in parts) or '\\' in remote:
        raise ValueError('Use a workspace-relative path without dot segments')
    return base + '/dav/' + workspace + '/' + '/'.join(url.quote(p, safe='') for p in parts)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', required=True, type=server)
    parser.add_argument('--profile', default='default')
    parser.add_argument('--credential-file', help='Managed Unix hosts only; mode 0600, never commit')
    sub = parser.add_subparsers(dest='command', required=True)
    auth = sub.add_parser('login'); auth.add_argument('--device-name', default='Codex - ' + socket.gethostname())
    sub.add_parser('import-password')
    sub.add_parser('devices')
    sub.add_parser('logout')
    revoke = sub.add_parser('revoke'); revoke.add_argument('id')
    for name in ('ls', 'get', 'put', 'mkdir', 'delete'):
        cmd = sub.add_parser(name)
        cmd.add_argument('--workspace', choices=['common-files', 'personal-files'], default='common-files')
        cmd.add_argument('path', nargs='?' if name == 'ls' else None, default='')
        if name in ('get', 'put'): cmd.add_argument('local')
    args = parser.parse_args()
    if args.command == 'login':
        login(args); return
    if args.command == 'import-password':
        username = input('Exact WebDAV username from the account panel: ').strip()
        password = getpass.getpass('Device password: ')
        metadata = device(args, password, 'list')['TriggerInfo']
        if metadata['username'] != username: raise RuntimeError('Username does not match credential owner')
        credential(args, {'server': args.server, 'username': username, 'password': password})
        print('Device password verified and saved; no secret printed.'); return
    current = credential(args)
    if args.command == 'devices':
        info = device(args, current['password'], 'list')['TriggerInfo']
        print(json.dumps({'username': info['username'], 'devices': json.loads(info['devices'])}, ensure_ascii=False, indent=2)); return
    if args.command in ('logout', 'revoke'):
        target = current.get('id') if args.command == 'logout' else args.id
        if not target: raise RuntimeError('Imported password has no ID; use devices then revoke <id> to revoke it')
        device(args, current['password'], 'revoke', id=target)
        if target == current.get('id'): forget(args)
        print('Device password revoked.'); return
    if args.command in ('delete', 'mkdir', 'put') and not args.path.strip('/'):
        raise RuntimeError('Refusing to mutate the workspace root')
    address = dav_address(args.server, args.workspace, args.path)
    basic = base64.b64encode((current['username'] + ':' + current['password']).encode()).decode()
    headers = {'Authorization': 'Basic ' + basic}
    method = {'ls': 'PROPFIND', 'get': 'GET', 'put': 'PUT', 'mkdir': 'MKCOL', 'delete': 'DELETE'}[args.command]
    if args.command == 'ls': headers['Depth'] = '1'
    if args.command in ('ls', 'mkdir') and not address.endswith('/'): address += '/'
    if args.command == 'put': headers['If-None-Match'] = '*'
    data = Path(args.local).read_bytes() if args.command == 'put' else None
    status, raw = request(method, address, headers, data)
    if args.command == 'get':
        with open(args.local, 'xb') as stream: stream.write(raw)
        print('Downloaded without overwriting a local file.')
    elif args.command == 'ls':
        document = ET.fromstring(raw)
        print(json.dumps([{'href': row.findtext('{DAV:}href'), 'status': row.findtext('.//{DAV:}status')}
            for row in document.findall('{DAV:}response')], ensure_ascii=False, indent=2))
    else: print('HTTP ' + str(status))


if __name__ == '__main__':
    try: main()
    except (Exception, KeyboardInterrupt) as error:
        # Never dump response bodies, parsed callback URLs or credential objects.
        safe = str(error) if isinstance(error, (RuntimeError, ValueError, FileExistsError, FileNotFoundError)) else type(error).__name__
        print('Failed: ' + safe, file=sys.stderr)
        sys.exit(1)
