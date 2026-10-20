"""Opt-in migration of one deliberately narrow, fully recognized legacy firewall."""
from copy import deepcopy
import re
import shlex

from .network_policy import NetworkPolicy, expected_state, normalize, ports


def source(tcp, *, retained=False):
    lines = ['destroy table inet filter', 'table inet filter {']
    if not retained:
        lines += ['chain input {', 'type filter hook input priority filter; policy drop;',
                  'iifname "lo" accept', 'ct state invalid drop', 'ct state established,related accept',
                  'ip protocol icmp accept', 'meta l4proto ipv6-icmp accept',
                  'tcp dport { ' + ', '.join(map(str, tcp)) + ' } accept', '}']
    lines += ['chain forward { type filter hook forward priority filter; policy drop; }',
              'chain output { type filter hook output priority filter; policy accept; }', '}', '']
    return '\n'.join(lines)


def tokens(text):
    lexer = shlex.shlex(text, posix=True, punctuation_chars='{};,')
    lexer.whitespace_split = True
    # Treat quoted/unquoted "lo" identically; comments have no packet semantics.
    return [part for token in lexer for part in (list(token) if re.fullmatch(r'[{};,]+', token) else [token])]


def objects(tcp, *, retained=False):
    own = expected_state(NetworkPolicy('custom', tuple(tcp), (), ()))
    result = [{'table': {'family': 'inet', 'name': 'filter'}}]
    for name, policy in (('forward', 'drop'), ('output', 'accept')):
        result.append({'chain': {'family': 'inet', 'table': 'filter', 'name': name,
                                'type': 'filter', 'hook': name, 'prio': 0, 'policy': policy}})
    if not retained:
        for item in own:
            kind, obj = next(iter(deepcopy(item).items()))
            if kind == 'chain' or kind == 'rule':
                obj['table'] = 'filter'
                if kind == 'rule' and obj['expr'][0].get('match', {}).get('right') == '@allowed_udp':
                    continue
                if kind == 'rule' and obj['expr'][0].get('match', {}).get('right') == '@allowed_tcp':
                    obj['expr'][0]['match']['right'] = {'set': list(tcp)} if len(tcp) > 1 else tcp[0]
                result.append({kind: obj})
    return normalize(result)


def table_objects(rules):
    return normalize([item for item in rules if next(iter(item.values())).get('family') == 'inet'
                      and (item.get('table', {}).get('name') == 'filter'
                           or next(iter(item.values())).get('table') == 'filter')])


def validate(record):
    if not isinstance(record, dict) or set(record) != {'tcp', 'source', 'mode', 'gid'} or not isinstance(record['source'], str):
        raise ValueError('Invalid legacy migration record')
    if type(record['mode']) is not int or not 0 <= record['mode'] <= 0o777 or record['mode'] & 0o022 or type(record['gid']) is not int or not 0 <= record['gid'] < 2**32-1:
        raise ValueError('Unsupported legacy file permissions or group')
    tcp = ports(record['tcp'], 'legacy tcp', empty=False)
    candidates = [source(tcp)]
    if len(tcp) == 1:
        candidates += [source(tcp).replace('{ ' + str(tcp[0]) + ' }', str(tcp[0]))]
    if tokens(record['source']) not in [tokens(candidate) for candidate in candidates]:
        raise ValueError('Legacy source is outside the supported exact template')
    return record


def recognize(rules, text, *, mode=0o644, gid=0):
    legacy = table_objects(rules)
    tcp = None
    for item in legacy:
        for expr in item.get('rule', {}).get('expr', []):
            match = expr.get('match', {})
            if match.get('left') == {'payload': {'protocol': 'tcp', 'field': 'dport'}}:
                right = match.get('right')
                tcp = right.get('set') if isinstance(right, dict) else [right]
    if tcp is None:
        raise ValueError('Legacy inet filter has no supported TCP allowance')
    record = validate({'tcp': tcp, 'source': text, 'mode': mode, 'gid': gid})
    if legacy != objects(record['tcp']):
        raise ValueError('Legacy inet filter contains unknown rules, objects, or chain semantics')
    return record


def detach():
    # Both operations and the new owned table are submitted in ONE netlink batch.
    return 'flush chain inet filter input\ndelete chain inet filter input\n'


def restore(record, current):
    """Restore only the adopted input chain; retain other chains and foreign tables."""
    validate(record)
    legacy = table_objects(current)
    if legacy == objects(record['tcp']):
        return ''
    if legacy == []:
        return source(record['tcp'])
    if legacy != objects(record['tcp'], retained=True):
        raise ValueError('Legacy table drift prevents safe rollback; journal retained')
    lines = ['add chain inet filter input { type filter hook input priority filter; policy drop; }']
    body = source(record['tcp']).split('policy drop;\n', 1)[1].split('\n}', 1)[0]
    lines += ['add rule inet filter input ' + line for line in body.splitlines()]
    return '\n'.join(lines) + '\n'
