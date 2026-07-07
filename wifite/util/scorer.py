_ENC_SCORE = {
    'WEP':  90,
    'WPS':  75,
    'WPA':  40,
    'WPA2': 40,
    'WPA3': 10,
}

_SIGNAL_THRESHOLDS = [
    (-50,  30),
    (-60,  20),
    (-70,  10),
    (-80,   5),
    (-100,  0),
]

_LABEL_COLOR = {
    'CRITICAL': '\033[91m',
    'HIGH':     '\033[33m',
    'MEDIUM':   '\033[93m',
    'LOW':      '\033[94m',
    'MINIMAL':  '\033[2m',
}
_RESET = '\033[0m'


def _signal_score(power_db):
    try:
        db = int(power_db)
    except (TypeError, ValueError):
        return 0
    for threshold, pts in _SIGNAL_THRESHOLDS:
        if db >= threshold:
            return pts
    return 0


def score(target):
    enc = (target.encryption or '').upper()
    pts = _ENC_SCORE.get(enc, 20)

    pts += _signal_score(target.power)

    if getattr(target, 'wps', 0):
        pts += 20

    pmf = getattr(target, 'pmf', False)
    pmf_req = getattr(target, 'pmf_required', False)
    if pmf_req:
        pts -= 15
    elif pmf:
        pts -= 5

    wpa3 = getattr(target, 'wpa3', False)
    if wpa3:
        pts -= 20

    clients = len(target.clients) if hasattr(target, 'clients') and isinstance(target.clients, list) else 0
    if clients > 0:
        pts += min(clients * 5, 20)

    return max(0, min(100, pts))


def label(pts):
    if pts >= 80:
        return 'CRITICAL'
    if pts >= 60:
        return 'HIGH'
    if pts >= 40:
        return 'MEDIUM'
    if pts >= 20:
        return 'LOW'
    return 'MINIMAL'


def badge(pts):
    lbl = label(pts)
    color = _LABEL_COLOR.get(lbl, '')
    bar_len = pts // 10
    bar = '█' * bar_len + '░' * (10 - bar_len)
    return '%s[%s] %s%s' % (color, bar, lbl, _RESET)


def sort_targets(targets):
    return sorted(targets, key=lambda t: score(t), reverse=True)
