import re
import os
import tempfile


_ISP_PATTERNS = [
    (re.compile(r'INFINITUM([0-9A-Fa-f]{8})', re.I), 'infinitum'),
    (re.compile(r'IZZI-?([0-9A-Fa-f]{4,8})', re.I),  'izzi'),
    (re.compile(r'Totalplay-?([0-9A-Fa-f]{4,8})', re.I), 'totalplay'),
    (re.compile(r'TP-Link[_-]([0-9A-Fa-f]{4,8})', re.I), 'tp-link-ssid'),
    (re.compile(r'movistar[_-]([0-9A-Fa-f]{4,8})', re.I), 'movistar'),
    (re.compile(r'Telmex([0-9A-Fa-f]{6,10})', re.I),  'telmex'),
    (re.compile(r'Megacable-?([0-9A-Fa-f]{4,8})', re.I), 'megacable'),
    (re.compile(r'ARRIS-([0-9A-Fa-f]{4,6})', re.I),   'arris-ssid'),
    (re.compile(r'Hitron-([0-9A-Fa-f]{4})', re.I),    'hitron'),
    (re.compile(r'HOME-([0-9A-Fa-f]{4})', re.I),      'generic-home'),
    (re.compile(r'NETGEAR([0-9]+)', re.I),             'netgear-ssid'),
    (re.compile(r'Vodafone-?([0-9A-Fa-f]{4,8})', re.I),'vodafone'),
    (re.compile(r'CLARO[_-]?([0-9A-Fa-f]{4,8})', re.I),'claro'),
    (re.compile(r'AXTEL[_-]?([0-9A-Fa-f]{4,8})', re.I),'axtel'),
    (re.compile(r'SKY[_-]?([0-9A-Fa-f]{4,8})', re.I), 'sky'),
    (re.compile(r'UNO([0-9]{6,10})', re.I),           'unotelecom'),
    (re.compile(r'IZZI([0-9]{6,10})', re.I),          'izzi-num'),
    (re.compile(r'([0-9]{8,12})', re.I),               'numeric-ssid'),
]


def _candidates_infinitum(match, bssid):
    token = match.group(1)
    cands = {token, token.upper(), token.lower()}
    digits = re.sub(r'[^0-9]', '', token)
    if len(digits) >= 8:
        cands.add(digits[:8])
        cands.add(digits[-8:])
    return cands


def _candidates_izzi(match, bssid):
    token = match.group(1).upper()
    bclean = bssid.replace(':', '').replace('-', '').upper()
    cands = {
        token, token.lower(),
        bclean[-8:], bclean[-10:],
    }
    digits = re.sub(r'[^0-9]', '', token)
    if digits:
        cands.add(digits)
        cands.add(digits.zfill(8))
    return cands


def _candidates_totalplay(match, bssid):
    token = match.group(1).upper()
    bclean = bssid.replace(':', '').replace('-', '').upper()
    cands = {token, token.lower(), bclean[-8:], bclean[-10:]}
    return cands


def _candidates_tplink_ssid(match, bssid):
    token = match.group(1).upper()
    bclean = bssid.replace(':', '').replace('-', '').upper()
    cands = {
        token, token.lower(),
        bclean[-8:], bclean[-8:].upper(),
    }
    return cands


def _candidates_movistar(match, bssid):
    token = match.group(1).upper()
    bclean = bssid.replace(':', '').replace('-', '').upper()
    cands = {token, token.lower(), bclean[-8:], bclean[-10:]}
    return cands


def _candidates_numeric(match, bssid):
    token = match.group(1)
    cands = {token}
    if len(token) > 8:
        cands.add(token[:8])
        cands.add(token[-8:])
    if len(token) > 10:
        cands.add(token[:10])
        cands.add(token[-10:])
    return cands


def _candidates_generic(match, bssid):
    token = match.group(1).upper()
    bclean = bssid.replace(':', '').replace('-', '').upper()
    cands = {
        token, token.lower(),
        bclean[-6:], bclean[-8:], bclean[-10:],
    }
    return cands


_ISP_GENERATORS = {
    'infinitum':    _candidates_infinitum,
    'izzi':         _candidates_izzi,
    'izzi-num':     _candidates_izzi,
    'totalplay':    _candidates_totalplay,
    'tp-link-ssid': _candidates_tplink_ssid,
    'movistar':     _candidates_movistar,
    'telmex':       _candidates_infinitum,
    'megacable':    _candidates_generic,
    'arris-ssid':   _candidates_generic,
    'hitron':       _candidates_generic,
    'generic-home': _candidates_generic,
    'netgear-ssid': _candidates_numeric,
    'vodafone':     _candidates_generic,
    'claro':        _candidates_generic,
    'axtel':        _candidates_generic,
    'sky':          _candidates_generic,
    'unotelecom':   _candidates_numeric,
    'numeric-ssid': _candidates_numeric,
}


def detect_isp(essid):
    for pattern, isp_key in _ISP_PATTERNS:
        m = pattern.search(essid or '')
        if m:
            return isp_key, m
    return None, None


def generate(essid, bssid):
    isp_key, match = detect_isp(essid)
    candidates = set()

    if isp_key and match:
        gen_fn = _ISP_GENERATORS.get(isp_key, _candidates_generic)
        candidates.update(gen_fn(match, bssid))

    bclean = bssid.replace(':', '').replace('-', '').upper()
    candidates.update({
        bclean[-8:], bclean[-10:], bclean[-12:],
        bclean[-8:].lower(), bclean[-10:].lower(),
    })

    return sorted(c for c in candidates if 8 <= len(c) <= 63), isp_key


def write_targeted_wordlist(essid, bssid):
    candidates, isp_key = generate(essid, bssid)
    if not candidates:
        return None, None
    fd, path = tempfile.mkstemp(prefix='wifite_target_', suffix='.txt')
    os.close(fd)
    os.chmod(path, 0o600)
    with open(path, 'w') as f:
        for c in candidates:
            f.write(c + '\n')
    return path, isp_key
