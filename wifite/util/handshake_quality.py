import os
import struct

try:
    from scapy.all import rdpcap, Dot11, EAPOL
    _SCAPY = True
except ImportError:
    _SCAPY = False


QUALITY_FULL    = 'FULL'
QUALITY_PARTIAL = 'PARTIAL'
QUALITY_WEAK    = 'WEAK'
QUALITY_INVALID = 'INVALID'

_RESET  = '\033[0m'
_GREEN  = '\033[92m'
_YELLOW = '\033[93m'
_RED    = '\033[91m'
_CYAN   = '\033[96m'
_DIM    = '\033[2m'
_BOLD   = '\033[1m'


def _mic_is_zero(eapol_raw):
    try:
        if len(eapol_raw) < 99:
            return True
        mic_field = eapol_raw[81:97]
        return all(b == 0 for b in mic_field)
    except Exception:
        return True


def analyze(capfile, bssid=None):
    if not _SCAPY:
        return _fallback_result()
    if not os.path.isfile(capfile):
        return _result(QUALITY_INVALID, {}, 'Capture file not found')

    try:
        packets = rdpcap(capfile)
    except Exception as e:
        return _result(QUALITY_INVALID, {}, 'Failed to parse capture: %s' % str(e))

    msg_counts   = {1: 0, 2: 0, 3: 0, 4: 0}
    mic_valid    = {1: False, 2: False, 3: False, 4: False}
    frame_detail = []

    for pkt in packets:
        if not pkt.haslayer(EAPOL):
            continue
        if bssid:
            src = None
            if pkt.haslayer(Dot11):
                src = pkt[Dot11].addr2
            if src and src.lower() not in (bssid.lower(), bssid.lower().replace(':', '-')):
                continue

        try:
            eapol_layer = pkt[EAPOL]
            raw = bytes(eapol_layer)
            if len(raw) < 4:
                continue
            key_info_offset = 3
            if len(raw) < key_info_offset + 2:
                continue
            key_info = struct.unpack('!H', raw[key_info_offset:key_info_offset+2])[0]
            msg_num = _eapol_message_number(key_info)
            if msg_num not in (1, 2, 3, 4):
                continue
            mic_zero = _mic_is_zero(raw)
            msg_counts[msg_num] += 1
            if not mic_zero:
                mic_valid[msg_num] = True
            frame_detail.append({'msg': msg_num, 'mic_valid': not mic_zero})
        except Exception:
            continue

    quality   = _classify(msg_counts, mic_valid)
    return _result(quality, msg_counts, None, mic_valid, frame_detail)


def _eapol_message_number(key_info):
    ack  = bool(key_info & 0x0080)
    mic  = bool(key_info & 0x0100)
    inst = bool(key_info & 0x0040)
    enc  = bool(key_info & 0x0010)
    if ack and not mic and not inst:
        return 1
    if not ack and mic and not inst:
        return 2
    if ack and mic and inst:
        return 3
    if not ack and mic and inst:
        return 4
    return 0


def _classify(counts, mic_valid):
    has1 = counts[1] > 0
    has2 = counts[2] > 0
    has3 = counts[3] > 0
    has4 = counts[4] > 0

    mic2_ok = mic_valid.get(2, False)
    mic4_ok = mic_valid.get(4, False)

    if (has1 and has2 and has3 and has4) or (has1 and has2 and has3):
        if mic2_ok:
            return QUALITY_FULL
        return QUALITY_PARTIAL
    if (has1 and has2) or (has2 and has3):
        if mic2_ok:
            return QUALITY_PARTIAL
        return QUALITY_WEAK
    if any(counts[m] > 0 for m in (1, 2, 3, 4)):
        return QUALITY_WEAK
    return QUALITY_INVALID


def _result(quality, counts, error=None, mic_valid=None, frames=None):
    return {
        'quality':   quality,
        'counts':    counts,
        'mic_valid': mic_valid or {},
        'frames':    frames or [],
        'error':     error,
    }


def _fallback_result():
    return _result(QUALITY_PARTIAL, {}, 'Scapy not available — skipping deep analysis')


def _quality_color(quality):
    return {
        QUALITY_FULL:    _GREEN,
        QUALITY_PARTIAL: _YELLOW,
        QUALITY_WEAK:    _RED,
        QUALITY_INVALID: _RED,
    }.get(quality, _DIM)


def render_report(result):
    q     = result['quality']
    color = _quality_color(q)
    lines = []
    lines.append('%s Handshake Quality: %s%s%s%s' % (
        _BOLD, color, q, _RESET, _BOLD))
    if result.get('error'):
        lines.append('  %s%s%s' % (_RED, result['error'], _RESET))
    counts = result.get('counts', {})
    if counts:
        msgs = []
        for m in (1, 2, 3, 4):
            n = counts.get(m, 0)
            mic = result.get('mic_valid', {}).get(m, False)
            if n > 0:
                mic_tag = '%s✔MIC%s' % (_GREEN, _DIM) if mic else '%s✘MIC%s' % (_RED, _DIM)
                msgs.append('%sMsg%d×%d%s %s' % (_CYAN, m, n, _RESET, mic_tag))
        lines.append('  ' + _DIM + '  '.join(msgs) + _RESET)

    if q == QUALITY_INVALID:
        lines.append('  %s⚠ No valid EAPOL frames found — capture is unusable%s' % (_RED, _RESET))
    elif q == QUALITY_WEAK:
        lines.append('  %s⚠ Single EAPOL message — cracking will likely fail%s' % (_YELLOW, _RESET))
    elif q == QUALITY_PARTIAL:
        lines.append('  %s⚑ Partial exchange captured — cracking possible%s' % (_YELLOW, _RESET))
    elif q == QUALITY_FULL:
        lines.append('  %s✔ Complete 4-way exchange — optimal for cracking%s' % (_GREEN, _RESET))

    return '\n'.join(lines)
