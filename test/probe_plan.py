"""Strict YAML test plans, normalized to the existing native launch contract."""
import hashlib
import importlib
import ipaddress
import json
import math
import fcntl
import os
from urllib.parse import urlsplit
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
YAML_VERSION = '6.0.3'
YAML_SHA = 'd76623373421df22fb4cf8817020cbb7ef15c725b9d5e45f17e189bfc384190f'
YAML_URL = 'https://files.pythonhosted.org/packages/05/8e/961c0007c59b8dd7729d542c61a4d537767a59645b82a0b521206e1e25c2/pyyaml-6.0.3.tar.gz'
IDENT = re.compile(r'[a-z][a-z0-9-]{0,127}\Z')
ACCOUNT = re.compile(r'[a-z_][a-z0-9_-]{0,127}\Z')
ACTIONS = {'fetch', 'file', 'exec', 'service', 'listeners', 'mount'}

CAP_NAMES = ('chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap '
             'linux_immutable net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner '
             'sys_module sys_rawio sys_chroot sys_ptrace sys_pacct sys_admin sys_boot sys_nice '
             'sys_resource sys_time sys_tty_config mknod lease audit_write audit_control setfcap '
             'mac_override mac_admin syslog wake_alarm block_suspend audit_read perfmon bpf '
             'checkpoint_restore').split()


def yaml_module():
    cache = ROOT / "out/test-yaml" / YAML_VERSION
    cache.mkdir(parents=True, exist_ok=True)
    with (cache / "lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _yaml_module()


def _yaml_module():
    """Load the pinned pure-Python parser without installing into the host Python."""
    cache = ROOT / 'out/test-yaml' / YAML_VERSION
    archive = cache / 'source.tar.gz'
    cache.mkdir(parents=True, exist_ok=True)
    if not archive.exists():
        with tempfile.TemporaryDirectory(dir=cache) as directory:
            temporary = Path(directory) / "source.tar.gz"
            subprocess.run(['curl', '-fsSL', '--proto', '=https', YAML_URL,
                            '-o', str(temporary)], check=True)
            raw = temporary.read_bytes()
            if hashlib.sha256(raw).hexdigest() != YAML_SHA:
                raise ValueError('test YAML parser checksum mismatch')
            os.replace(temporary, archive)
    raw = archive.read_bytes()
    if hashlib.sha256(raw).hexdigest() != YAML_SHA:
        raise ValueError('test YAML parser checksum mismatch')
    # Extract only Python modules, never archive links or installation scripts.
    with tarfile.open(archive) as package:
        for member in package:
            prefix = 'pyyaml-' + YAML_VERSION + '/lib/yaml/'
            if member.name.startswith(prefix) and member.isfile():
                name = member.name[len(prefix):]
                if '/' in name or not name.endswith('.py'):
                    continue
                target = cache / 'yaml' / name
                target.parent.mkdir(exist_ok=True)
                content = package.extractfile(member).read()
                if not target.exists() or target.read_bytes() != content:
                    target.write_bytes(content)
    sys.path.insert(0, str(cache))
    module = importlib.import_module('yaml')
    if Path(module.__file__).resolve().parent != (cache / 'yaml').resolve():
        raise ValueError('test plans require the pinned YAML parser')
    return module


def load(path):
    yaml = yaml_module()

    class Loader(yaml.BaseLoader):
        pass

    def mapping(loader, node):
        result = {}
        for key, value in node.value:
            if key.tag != 'tag:yaml.org,2002:str' or not isinstance(key, yaml.ScalarNode):
                raise ValueError('mapping keys must be strings')
            if key.value in result:
                raise ValueError(f'{path}:{key.start_mark.line + 1}: duplicate key {key.value}')
            result[key.value] = loader.construct_object(value, deep=True)
        return result

    def scalar(loader, node):
        value = node.value
        if node.style is not None:
            return value
        if value in ('true', 'false'):
            return value == 'true'
        if value == 'null':
            return None
        if re.fullmatch(r'-?(0|[1-9][0-9]*)', value):
            return int(value)
        if re.fullmatch(r'-?(0|[1-9][0-9]*)\.[0-9]+', value):
            return float(value)
        implicit = yaml.SafeLoader.yaml_implicit_resolvers.get(value[:1], [])
        if any(tag != 'tag:yaml.org,2002:str' and pattern.match(value)
               for tag, pattern in implicit) or re.fullmatch(r'[+-]?[0-9]+[eE][+-]?[0-9]+', value):
            raise ValueError(f'{path}:{node.start_mark.line + 1}: quote ambiguous scalar {value}')
        return value

    Loader.add_constructor('tag:yaml.org,2002:map', mapping)
    Loader.add_constructor('tag:yaml.org,2002:str', scalar)
    raw = path.read_text()
    if len(raw.encode()) > 256 << 10:
        raise ValueError('test plan exceeds 256 KiB')
    depth = 0
    try: tokens = list(yaml.scan(raw))
    except yaml.YAMLError as error: raise ValueError(str(error)) from error
    for token in tokens:
        if isinstance(token, (yaml.BlockMappingStartToken, yaml.BlockSequenceStartToken, yaml.FlowMappingStartToken, yaml.FlowSequenceStartToken)):
            depth += 1
        elif isinstance(token, (yaml.BlockEndToken, yaml.FlowMappingEndToken, yaml.FlowSequenceEndToken)):
            depth -= 1
        if depth > 32:
            raise ValueError("test plan nesting exceeds 32 levels")
        if isinstance(token, (yaml.AliasToken, yaml.AnchorToken, yaml.TagToken)):
            raise ValueError(f'{path}:{token.start_mark.line + 1}: YAML aliases/tags are forbidden')
    try:
        data = yaml.load(raw, Loader=Loader)
        node = yaml.compose(raw, Loader=Loader)
    except yaml.YAMLError as error:
        raise ValueError(str(error)) from error
    locations = {}

    def walk(item, trail=()):
        locations[trail] = item.start_mark.line + 1
        if isinstance(item, yaml.MappingNode):
            for key, value in item.value:
                walk(value, trail + (key.value,))
        elif isinstance(item, yaml.SequenceNode):
            for i, value in enumerate(item.value):
                walk(value, trail + (i,))
    if node is None: raise ValueError("empty test plan")
    walk(node)
    return normalize(data, path, locations)


def fields(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or not set(required) <= set(value):
        raise ValueError('invalid fields: expected ' + ', '.join(sorted(allowed)))


def identity(value):
    if not isinstance(value, str) or not IDENT.fullmatch(value):
        raise ValueError('invalid test identity')
    return value


def absolute(value):
    if not isinstance(value, str) or not value.startswith('/') or '..' in Path(value).parts or '\x00' in value:
        raise ValueError('expected explicit absolute path')
    return value


def strings(values):
    if not isinstance(values, list) or any(not isinstance(v, str) or '\x00' in v for v in values):
        raise ValueError('expected string list')
    return values


def references(value, previous, fixtures):
    if isinstance(value, dict):
        if 'run' in value:
            fields(value, {'run'}, {'run'})
            if value['run'] is not True: raise ValueError('run selector must be true')
        elif 'step' in value:
            fields(value, {'step', 'json', 'header', 'cookie', 'body'}, {'step'})
            if not isinstance(value['step'], str) or value['step'] not in previous or len(value) != 2:
                raise ValueError('capture must select an earlier named step')
            selector = next(key for key in value if key != 'step')
            sources = {'json': {'fetch', 'file', 'exec'}, 'body': {'fetch', 'file'},
                       'header': {'fetch'}, 'cookie': {'fetch'}}
            if previous[value['step']] not in sources[selector]:
                raise ValueError('capture selector is unavailable for the selected probe')
            for key, selector in value.items():
                if key == 'json': pointer(selector)
                elif key == 'body' and selector is not True: raise ValueError('body selector must be true')
                elif key in ('header', 'cookie'): string(selector)
            if 'header' in value: value['header'] = value['header'].lower()
        elif 'fixture' in value:
            fields(value, {'fixture', 'raw'}, {'fixture'})
            if 'raw' in value and value['raw'] is not True:
                raise ValueError('raw fixture selector must be true')
            if not isinstance(value['fixture'], str) or value['fixture'] not in fixtures:
                raise ValueError('unknown fixture')
        else:
            for v in value.values(): references(v, previous, fixtures)
    elif isinstance(value, list):
        for v in value: references(v, previous, fixtures)


MATCHERS = {'equals', 'contains', 'contains_all', 'contains_none', 'absent', 'one_of', 'min', 'max', 'matches', 'not_matches', 'count', 'occurrences', 'type'}


def string(value):
    if not isinstance(value, str) or '\x00' in value:
        raise ValueError('expected NUL-free string')
    return value


def literal(value, depth=0):
    if depth > 32: raise ValueError('value nesting exceeds 32 levels')
    if isinstance(value, dict):
        for k, v in value.items(): string(k); literal(v, depth+1)
    elif isinstance(value, list):
        for v in value: literal(v, depth+1)
    elif type(value) is int:
        if not -(1 << 53) < value < (1 << 53): raise ValueError('integer exceeds exact numeric range')
    elif type(value) is float:
        if not math.isfinite(value): raise ValueError('nonfinite number')
    elif isinstance(value, str): string(value)
    elif value is not None and type(value) is not bool: raise ValueError('invalid value')


def pointer(value):
    string(value)
    if value and not value.startswith('/') or re.search(r'~(?![01])', value):
        raise ValueError('invalid JSON pointer')
    if any(len(part.encode()) > 1024 for part in value.split('/')):
        raise ValueError('JSON pointer segment too long')


def matcher(value):
    literal(value)
    if not isinstance(value, dict) or not set(value) & MATCHERS: return
    fields(value, MATCHERS)
    for key, v in value.items():
        if key in ('min', 'max') and type(v) not in (int, float):
            raise ValueError('numeric matcher requires number')
        if key == 'count' and (type(v) is not int or v < 0):
            raise ValueError('count requires nonnegative integer')
        if key == 'one_of' and (not isinstance(v, list) or not v):
            raise ValueError('one_of requires nonempty list')
        if key in ('contains_all', 'contains_none') and (not isinstance(v, list) or not v):
            raise ValueError(key + ' requires nonempty list')
        if key == 'type' and (not isinstance(v, str) or v not in ('null', 'bool', 'integer', 'float', 'string', 'array', 'object')):
            raise ValueError('invalid type matcher')
        if key in ('matches', 'not_matches') and (not isinstance(v, str) or len(v.encode()) > 512):
            raise ValueError('regex exceeds 512 bytes')
        if key == 'occurrences':
            if not isinstance(v, dict) or not v:
                raise ValueError('occurrences requires literal strings and counts')
            for needle, count in v.items():
                if not string(needle) or type(count) is not int or count < 0:
                    raise ValueError('occurrences requires nonempty strings and nonnegative counts')


def text_matcher(value):
    if isinstance(value, dict):
        if not set(value) & {'run', 'step', 'fixture'}:
            if not value: raise ValueError('empty text matcher')
            fields(value, MATCHERS)
    elif value is not None and not isinstance(value, str):
        raise ValueError('text assertion requires a string, null, reference or matcher')
    matcher(value)


def text_input(value):
    if isinstance(value, dict) and set(value) & {'step', 'fixture', 'run'}: return
    string(value)


def text_map(value, headers=False):
    if not isinstance(value, dict): raise ValueError('expected text mapping')
    for key, v in value.items():
        string(key)
        if headers and not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise ValueError('invalid header name')
        text_input(v)
        if headers and isinstance(v, str) and any(c in v for c in '\r\n'):
            raise ValueError('invalid header value')


def request_fields(action, request):
    if action == 'fetch':
        url = urlsplit(request['url'])
        if not url.hostname or url.username is not None or url.fragment or any(ord(c) <= 32 for c in request['url']):
            raise ValueError('URL needs hostname, no userinfo/fragment/control characters')
        try: port = url.port
        except ValueError as error: raise ValueError('invalid URL port') from error
        if port is not None and not 1 <= port <= 65535: raise ValueError('invalid URL port')
        if 'path' in request:
            if url.path not in ('', '/') or '?' in request['url'] or '#' in request['url']:
                raise ValueError('path requires a literal origin without path or query')
            parts = request['path']
            if not isinstance(parts, list) or not 1 <= len(parts) <= 32:
                raise ValueError('path requires 1..32 segments')
            for index, part in enumerate(parts):
                text_input(part)
                if isinstance(part, str) and (len(part.encode()) > 1024 or
                        part in ('.', '..') or not part and index != len(parts) - 1):
                    raise ValueError('invalid path segment')
        for key in ('body', 'bearer'):
            if key in request: text_input(request[key])
        if 'authorization' in request:
            auth = request['authorization']
            fields(auth, {'scheme', 'credentials'}, {'scheme', 'credentials'})
            if not isinstance(auth['scheme'], str) or not re.fullmatch(
                    r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", auth['scheme']):
                raise ValueError('invalid authorization scheme')
            text_input(auth['credentials'])
        if 'session' in request: identity(request['session'])
        if 'resolve' in request: strings(request['resolve'])
        if 'headers' in request: text_map(request['headers'], headers=True)
        if ('bearer' in request and 'authorization' in request or
                set(request) & {'bearer', 'authorization'} and any(
                    k.lower() == 'authorization' for k in request.get('headers', {}))):
            raise ValueError('choose one authorization source')
        if 'form' in request: text_map(request['form'])
        if 'multipart' in request:
            if not isinstance(request['multipart'], dict): raise ValueError('multipart requires mapping')
            for key, value in request['multipart'].items():
                string(key)
                if isinstance(value, dict) and 'file' in value:
                    fields(value, {'file', 'type', 'filename'}, {'file'})
                    absolute(value['file'])
                    for k in ('type', 'filename'):
                        if k in value: string(value[k])
                else: text_input(value)
        if request.get('method', 'GET') == 'HEAD' and set(request) & {'body', 'json', 'form', 'multipart'}:
            raise ValueError('HEAD cannot have a body')
    elif action == 'exec':
        for arg in request['argv']: text_input(arg)
        if 'stdin' in request: text_input(request['stdin'])
        if 'readonly' in request and type(request['readonly']) is not bool: raise ValueError('readonly must be boolean')
        if 'env' in request:
            text_map(request['env'])
            for key in request['env']:
                if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', key): raise ValueError('invalid environment name')


def expectations(action, expect):
    for key, value in expect.items():
        if key == 'json':
            if not isinstance(value, dict) or not value: raise ValueError('json requires pointer/assertion map')
            for path, comparison in value.items(): pointer(path); matcher(comparison)
        elif key in ('headers', 'cookies'):
            if not isinstance(value, dict) or not value: raise ValueError(key + ' requires assertion map')
            if key == 'headers' and any(k != k.lower() for k in value): raise ValueError('response header names must be lowercase')
            for comparison in value.values(): text_matcher(comparison)
        elif key in ('body', 'stdout', 'stderr'): text_matcher(value)
        elif action == 'service' and key == 'user':
            if type(value) is int:
                if not 0 <= value < 1 << 32: raise ValueError('invalid user ID')
            elif not isinstance(value, str) or not ACCOUNT.fullmatch(value): raise ValueError('invalid user name')
        elif action == 'service' and key == 'groups':
            if isinstance(value, list):
                group_values = value
            else:
                fields(value, {'contains', 'absent'})
                group_values = list(value.values())
            for v in group_values:
                if not ((type(v) is int and 0 <= v < 1 << 32) or (isinstance(v, str) and ACCOUNT.fullmatch(v))):
                    raise ValueError('groups requires group names or numeric IDs')
        elif action == 'mount' and key in ('flags', 'absent_flags'): strings(value)
        elif action == 'file' and key == 'readable':
            if type(value) is not bool: raise ValueError('readable requires a boolean')
        elif action != 'listeners': matcher(value)


def normalize(data, path, locations=None):
    locations = locations or {}
    literal(data)
    fields(data, {'version', 'packages', 'suites', 'legacy', 'timeout'}, {'version', 'suites'})
    if type(data['version']) is not int or data['version'] != 1:
        raise ValueError('unsupported test plan version')
    if type(data.get('legacy', False)) is not bool:
        raise ValueError('legacy must be boolean')
    timeout = data.get('timeout', '300s')
    if not isinstance(timeout, str) or not re.fullmatch(r'[1-9][0-9]*s', timeout) or int(timeout[:-1]) > 1800:
        raise ValueError('phase timeout must be 1s..1800s')
    phase_seconds = int(timeout[:-1])
    suites = data['suites']
    if not isinstance(suites, list) or len(suites) > 32:
        raise ValueError('expected 0..32 suites')
    packages = set(strings(data.get('packages', [])))
    drivers, names = [], set()
    for index, suite in enumerate(suites):
        fields(suite, {'name', 'user', 'groups', 'policy', 'fixtures', 'cases', 'source', 'mode', 'memory', 'allow', 'readiness'}, {'name'})
        if type(suite.get('readiness', False)) is not bool:
            raise ValueError('readiness must be boolean')
        name = identity(suite['name'])
        if not name.startswith('test-'): name = 'test-' + name
        if name in names: raise ValueError('duplicate suite')
        names.add(name)
        policy = suite.get('policy', {})
        fields(policy, {'pledge', 'read', 'connect', 'run'})
        d = dict(name=name, user=suite.get('user', 'root'), groups=suite.get('groups', []),
                 pledge=policy.get('pledge', 'stdio rpath'), read=policy.get('read', []),
                 connect=policy.get('connect', []), run=policy.get('run', []),
                 memory=suite.get('memory', 128), allow=suite.get('allow', []),
                 readiness=suite.get('readiness', False), config={})
        string(d['pledge'])
        for field in ('read', 'connect', 'run', 'groups', 'allow'): strings(d[field])
        if not isinstance(d['user'], str) or not ACCOUNT.fullmatch(d['user']): raise ValueError('invalid suite user')
        fixtures = suite.get('fixtures', {})
        if not isinstance(fixtures, dict): raise ValueError('fixtures must be a map')
        for key, value in fixtures.items():
            identity(key)
            absolute(value)
            if not value.startswith('/run/config/'):
                raise ValueError('fixtures must name /run/config files')
            d['config'][key] = value
        if 'source' in suite:
            if 'policy' not in suite or 'mode' not in suite:
                raise ValueError('native source requires mode/policy')
            d.update(source=suite['source'], mode=suite['mode'], cases=suite.get('cases'))
            drivers.append(d)
            continue
        if 'mode' in suite: raise ValueError('mode requires native source')
        cases = suite.get('cases')
        if not isinstance(cases, list) or not 1 <= len(cases) <= 256:
            raise ValueError('expected 1..256 cases')
        seen, normalized, phase_cases = set(), [], {'seed': [], 'verify': []}
        for ci, case in enumerate(cases):
            fields(case, {'name', 'phases', 'steps'}, {'name', 'steps'})
            cname = identity(case['name'])
            if cname in seen: raise ValueError('duplicate case')
            seen.add(cname)
            phases = case.get('phases', ['seed', 'verify'])
            strings(phases)
            if not phases or len(set(phases)) != len(phases) or set(phases) - {'seed', 'verify'}:
                raise ValueError('invalid phases')
            for phase in phases: phase_cases[phase].append(cname)
            steps = case['steps']
            if not isinstance(steps, list) or not 1 <= len(steps) <= 64:
                raise ValueError('expected 1..64 steps')
            previous, compiled = {}, []
            for si, step in enumerate(steps):
                fields(step, ACTIONS | {'name', 'expect', 'await', 'timeout'}, {'expect'})
                actions = set(step) & ACTIONS
                if len(actions) != 1: raise ValueError('step needs exactly one probe')
                action = next(iter(actions))
                sname = identity(step.get('name', 'step-' + str(si + 1)))
                if sname in previous: raise ValueError('duplicate step')
                references(step[action], previous, fixtures)
                wait = step.get('await', '0s')
                if not isinstance(wait, str) or not re.fullmatch(r'(0|[1-9][0-9]*)s', wait) or int(wait[:-1]) > phase_seconds:
                    raise ValueError('await must fit within the phase timeout')
                timeout = step.get('timeout', '10s')
                if not isinstance(timeout, str) or not re.fullmatch(r'[1-9][0-9]*s', timeout) or int(timeout[:-1]) > 300:
                    raise ValueError('timeout must be 1s..300s')
                if 'timeout' in step and action not in {'fetch', 'exec'}:
                    raise ValueError('timeout applies to fetch and exec')
                request = step[action]
                if action == 'fetch':
                    fields(request, {'url', 'path', 'method', 'headers', 'json', 'body', 'bearer', 'authorization', 'session', 'ca', 'resolve', 'form', 'multipart'}, {'url'})
                    if not isinstance(request['url'], str) or not request['url'].startswith(('http://', 'https://')):
                        raise ValueError('fetch requires a literal HTTP(S) URL')
                    method = request.get('method', 'GET')
                    if not isinstance(method, str) or method not in {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'PROPFIND'}:
                        raise ValueError('invalid HTTP method')
                    if sum(k in request for k in ('body', 'json', 'form', 'multipart')) > 1:
                        raise ValueError('choose one request body')
                    if int(wait[:-1]) and method not in {'GET', 'HEAD', 'OPTIONS'}:
                        raise ValueError('await cannot repeat an HTTP mutation')
                    if d['readiness'] and method not in {'GET', 'HEAD', 'OPTIONS'}:
                        raise ValueError('readiness requires read-only HTTP probes')
                    if 'ca' in request: absolute(request['ca'])
                    packages.add('libcurl-openssl4')
                elif action == 'exec':
                    fields(request, {'argv', 'stdin', 'env', 'readonly'}, {'argv'})
                    argv = request['argv']
                    if not isinstance(argv, list) or not argv: raise ValueError('exec requires argv')
                    absolute(argv[0])
                    if argv[0] not in d['run']: raise ValueError('exec client must be declared in policy.run')
                    if int(wait[:-1]) and request.get('readonly') is not True:
                        raise ValueError('await requires a declared read-only client operation')
                    if d['readiness'] and request.get('readonly') is not True:
                        raise ValueError('readiness requires a declared read-only client operation')
                elif action in {'file', 'mount'}:
                    absolute(request)
                elif action == 'service':
                    identity(request)
                elif action == 'listeners':
                    if isinstance(request, str):
                        protocol = request
                    else:
                        fields(request, {'protocol', 'port'}, {'protocol', 'port'})
                        protocol = request['protocol']
                        if type(request['port']) is not int or not 1 <= request['port'] <= 65535:
                            raise ValueError('invalid listener port')
                    if protocol not in ('tcp', 'udp', 'all'): raise ValueError('invalid listener protocol')
                request_fields(action, request)
                references(step['expect'], previous, fixtures)
                if not isinstance(step['expect'], dict) or not step['expect']:
                    raise ValueError('expect must be a nonempty mapping')
                allowed = {
                    'fetch': {'status', 'headers', 'cookies', 'body', 'json'},
                    'exec': {'exit', 'stdout', 'stderr', 'json'},
                    'file': {'exists', 'type', 'uid', 'gid', 'mode', 'size', 'body', 'json', 'link', 'entries', 'readable'},
                    'service': {'user', 'uid', 'groups', 'capabilities', 'no_new_privileges', 'seccomp', 'processes', 'pids_max', 'bounding_capabilities', 'connect_rules'},
                    'listeners': {'contains', 'absent', 'equals'},
                    'mount': {'type', 'source', 'flags', 'absent_flags'},
                }[action]
                fields(step['expect'], allowed)
                if action == 'service':
                    if isinstance(step['expect'].get('connect_rules'), list):
                        rules = strings(step['expect']['connect_rules'])
                        step['expect']['connect_rules'] = sorted(rules)
                    for key in ('capabilities', 'bounding_capabilities'):
                        if key in step['expect'] and isinstance(step['expect'][key], list):
                            caps = strings(step['expect'][key])
                            if len(set(caps)) != len(caps) or set(caps) - set(CAP_NAMES):
                                raise ValueError('invalid capability list')
                            step['expect'][key] = sum(1 << CAP_NAMES.index(c) for c in caps)
                if action == 'listeners':
                    for comparison, entries in step['expect'].items():
                        if not isinstance(entries, list) or (not entries and comparison != 'equals'):
                            raise ValueError('listeners require nonempty patterns, or equals: []')
                        for listener in entries:
                            required = {'protocol', 'address', 'port'} if comparison == 'equals' else set()
                            fields(listener, {'protocol', 'address', 'port'}, required)
                            if not listener: raise ValueError('empty listener pattern')
                            if 'protocol' in listener and listener['protocol'] not in ('tcp', 'udp'):
                                raise ValueError('invalid listener protocol')
                            if 'port' in listener and (type(listener['port']) is not int or not 1 <= listener['port'] <= 65535):
                                raise ValueError('invalid listener port')
                            if 'address' in listener:
                                address = ipaddress.ip_address(listener['address'])
                                listener['address'] = ':'.join(format(int(x, 16), 'x') for x in address.exploded.split(':')) if address.version == 6 else str(address)
                        if len({json.dumps(v, sort_keys=True) for v in entries}) != len(entries):
                            raise ValueError('duplicate listener')
                expectations(action, step['expect'])
                compiled.append(dict(name=sname, probe=action, request=request, expect=step['expect'],
                                     await_seconds=int(wait[:-1]), timeout_seconds=int(timeout[:-1]),
                                     line=locations.get(('suites', index, 'cases', ci, 'steps', si), 1)))
                previous[sname] = action
            normalized.append(dict(name=cname, phases=phases, steps=compiled))
        d.update(source='probes.zig', mode='probes', cases=phase_cases,
                 probes=dict(source=str(path), fixtures=fixtures if d['user'] == 'root' else {k: '/run/svc/' + name + '/' + k for k in fixtures}, cases=normalized))
        drivers.append(d)
    return dict(format='werewolf-native-tests/1', legacy=data.get('legacy', False), timeout_seconds=phase_seconds,
                packages=sorted(packages), drivers=drivers)
