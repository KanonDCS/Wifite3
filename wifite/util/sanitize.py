import re
import os


_BSSID_RE  = re.compile(r'^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$')
_CHAN_RE    = re.compile(r'^[0-9]{1,3}$')
_IFACE_RE  = re.compile(r'^[a-zA-Z0-9_\-]{1,20}$')


def bssid(value):
    if not value or not _BSSID_RE.match(value.strip()):
        raise ValueError('Invalid BSSID: %r' % value)
    return value.strip().upper()


def essid(value):
    if value is None:
        return ''
    sanitized = ''
    for ch in value:
        if ch.isprintable() and ch not in (';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\'):
            sanitized += ch
    return sanitized[:64]


def channel(value):
    s = str(value).strip()
    if not _CHAN_RE.match(s) or not (1 <= int(s) <= 196):
        raise ValueError('Invalid channel: %r' % value)
    return s


def interface(value):
    if not value or not _IFACE_RE.match(value.strip()):
        raise ValueError('Invalid interface name: %r' % value)
    return value.strip()


def wordlist_path(value):
    path = os.path.abspath(str(value).strip())
    if not os.path.isfile(path):
        raise ValueError('Wordlist not found: %r' % path)
    if not os.access(path, os.R_OK):
        raise ValueError('Wordlist not readable: %r' % path)
    return path


def cap_path(value):
    path = os.path.abspath(str(value).strip())
    allowed_exts = ('.cap', '.pcap', '.pcapng', '.hc22000')
    if not any(path.endswith(ext) for ext in allowed_exts):
        raise ValueError('Unsupported capture file extension: %r' % path)
    return path
