import re
import itertools
import string


_DIGITS  = string.digits
_UPPER   = string.ascii_uppercase
_LOWER   = string.ascii_lowercase
_ALNUM   = string.ascii_letters + string.digits


def _bssid_bytes(bssid):
    clean = bssid.replace(':', '').replace('-', '').upper()
    return [int(clean[i:i+2], 16) for i in range(0, 12, 2)]


def _essid_digits(essid):
    return re.sub(r'[^0-9]', '', essid or '')


def _essid_hex(essid):
    return re.sub(r'[^0-9a-fA-F]', '', essid or '').upper()


def _essid_suffix(essid, n=6):
    digits = _essid_digits(essid)
    return digits[-n:] if len(digits) >= n else None


def for_vendor(vendor_key, bssid, essid):
    candidates = set()

    if vendor_key == 'tp-link':
        candidates.update(_tp_link(bssid, essid))

    elif vendor_key == 'netgear':
        candidates.update(_netgear(bssid, essid))

    elif vendor_key == 'huawei':
        candidates.update(_huawei(bssid, essid))

    elif vendor_key == 'asus':
        candidates.update(_asus(bssid, essid))

    elif vendor_key == 'linksys':
        candidates.update(_linksys(bssid, essid))

    elif vendor_key == 'dlink':
        candidates.update(_dlink(bssid, essid))

    elif vendor_key in ('tenda', 'mercusys'):
        candidates.update(_tenda(bssid, essid))

    elif vendor_key == 'zte':
        candidates.update(_zte(bssid, essid))

    elif vendor_key in ('arris', 'motorola'):
        candidates.update(_arris(bssid, essid))

    elif vendor_key == 'mikrotik':
        candidates.update(_mikrotik(bssid, essid))

    candidates.update(_universal_patterns(bssid, essid))
    return sorted(c for c in candidates if 8 <= len(c) <= 63)


def _tp_link(bssid, essid):
    cands = set()
    suf = _essid_suffix(essid, 8)
    if suf and len(suf) == 8:
        cands.add(suf)
    digits = _essid_digits(essid)
    if len(digits) >= 8:
        cands.add(digits[-8:])
    for length in (8, 10):
        for combo in itertools.islice(
            (''.join(p) for p in itertools.product(_UPPER, repeat=length)), 0
        ):
            cands.add(combo)
    hex_suf = _essid_hex(essid)
    if len(hex_suf) >= 8:
        cands.add(hex_suf[:8].upper())
        cands.add(hex_suf[-8:].upper())
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    return cands


def _netgear(bssid, essid):
    cands = set()
    common_adj  = ['happy','sunny','brave','swift','smart','lucky','cool','fast','bold','calm']
    common_noun = ['dog','cat','bird','fish','bear','deer','wolf','frog','lion','star']
    for adj in common_adj:
        for noun in common_noun:
            for n in range(100, 1000):
                cands.add('%s%s%d' % (adj, noun, n))
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    cands.add(bssid_clean[-10:])
    return cands


def _huawei(bssid, essid):
    cands = set()
    bbs = _bssid_bytes(bssid)
    cands.add('%02X%02X%02X%02X%02X%02X' % tuple(bbs))
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    cands.add(bssid_clean[-10:])
    digits = _essid_digits(essid)
    if len(digits) >= 8:
        cands.add(digits[-8:])
        cands.add(digits[-10:] if len(digits) >= 10 else digits)
    for n in range(10000000, 99999999, 1111111):
        cands.add(str(n))
    return cands


def _asus(bssid, essid):
    cands = set()
    bssid_clean = bssid.replace(':', '').replace('-', '').lower()
    cands.add(bssid_clean)
    cands.add(bssid_clean.upper())
    cands.add('admin')
    cands.add('password')
    cands.add('1234567890')
    digits = _essid_digits(essid)
    if len(digits) >= 8:
        cands.add(digits[-8:])
    return cands


def _linksys(bssid, essid):
    cands = set()
    cands.update(['password', 'admin', 'linksys', 'cisco'])
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    return cands


def _dlink(bssid, essid):
    cands = set()
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    cands.add(bssid_clean[-10:])
    digits = _essid_digits(essid)
    if len(digits) >= 8:
        cands.add(digits[-8:])
    return cands


def _tenda(bssid, essid):
    cands = set()
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    cands.update(['12345678', '1234567890', 'password', 'admin123'])
    digits = _essid_digits(essid)
    if len(digits) >= 8:
        cands.add(digits[-8:])
    return cands


def _zte(bssid, essid):
    cands = set()
    bbs = _bssid_bytes(bssid)
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    cands.add(bssid_clean[-10:])
    cands.add('@Zte%s' % bssid_clean[-6:])
    cands.add('admin@%s' % bssid_clean[-6:])
    digits = _essid_digits(essid)
    if len(digits) >= 8:
        cands.add(digits[-8:])
        cands.add(digits[-10:] if len(digits) >= 10 else digits)
    return cands


def _arris(bssid, essid):
    cands = set()
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add('password')
    cands.add(bssid_clean[-10:])
    cands.add(bssid_clean[-8:])
    return cands


def _mikrotik(bssid, essid):
    cands = set()
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.add(bssid_clean[-8:])
    cands.add(bssid_clean[-10:])
    return cands


def _universal_patterns(bssid, essid):
    cands = set()
    bssid_clean = bssid.replace(':', '').replace('-', '').upper()
    cands.update([
        bssid_clean[-8:],
        bssid_clean[-10:],
        bssid_clean[-12:],
        bssid_clean.lower()[-8:],
    ])
    essid_digits = _essid_digits(essid)
    for n in range(4, 12):
        if len(essid_digits) >= n:
            cands.add(essid_digits[:n])
            cands.add(essid_digits[-n:])
    essid_clean = re.sub(r'[^a-zA-Z0-9]', '', essid or '')
    if len(essid_clean) >= 8:
        cands.add(essid_clean[:8].lower())
        cands.add(essid_clean[:8].upper())
    cands.update([
        '12345678', '123456789', '1234567890',
        '00000000', '11111111', '99999999',
        'password', 'password1', 'P@ssw0rd',
        'wifi1234', 'wifi12345',
        'admin123', 'admin1234',
    ])
    return cands


def write_wordlist(path, candidates):
    with open(path, 'w') as f:
        for c in candidates:
            f.write(c + '\n')
    return len(candidates)
