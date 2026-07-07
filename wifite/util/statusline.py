import sys
import time
import threading
import shutil


_RESET  = '\033[0m'
_GREEN  = '\033[92m'
_YELLOW = '\033[93m'
_CYAN   = '\033[96m'
_RED    = '\033[91m'
_DIM    = '\033[2m'
_BOLD   = '\033[1m'


def _term_width():
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


class ProgressBar:
    def __init__(self, total, width=20, fill='█', empty='░', color=_GREEN):
        self.total  = max(total, 1)
        self.width  = width
        self.fill   = fill
        self.empty  = empty
        self.color  = color

    def render(self, current):
        pct  = min(current / self.total, 1.0)
        done = int(self.width * pct)
        bar  = self.fill * done + self.empty * (self.width - done)
        return '%s[%s]%s %5.1f%%' % (self.color, bar, _RESET, pct * 100)


class StatusLine:
    def __init__(self):
        self._lock    = threading.Lock()
        self._active  = False
        self._parts   = {}
        self._order   = []
        self._thread  = None
        self._last_w  = 0

    def set(self, key, value, color=''):
        with self._lock:
            if key not in self._parts:
                self._order.append(key)
            self._parts[key] = (value, color)

    def remove(self, key):
        with self._lock:
            self._parts.pop(key, None)
            if key in self._order:
                self._order.remove(key)

    def _build(self):
        parts = []
        with self._lock:
            for key in self._order:
                val, color = self._parts.get(key, ('', ''))
                if color:
                    parts.append('%s%s%s' % (color, val, _RESET))
                else:
                    parts.append(val)
        line = '  ' + '  │  '.join(parts)
        w = _term_width()
        if len(line) > w:
            line = line[:w - 1]
        pad = max(0, self._last_w - len(line))
        self._last_w = len(line)
        return '\r' + line + ' ' * pad

    def _loop(self):
        while self._active:
            sys.stderr.write(self._build())
            sys.stderr.flush()
            time.sleep(0.25)

    def start(self):
        self._active = True
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self, newline=True):
        self._active = False
        if self._thread:
            self._thread.join()
        if newline:
            sys.stderr.write('\r' + ' ' * (_term_width() - 1) + '\r')
            sys.stderr.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


_global = StatusLine()


def update(key, value, color=''):
    _global.set(key, value, color)


def clear(key):
    _global.remove(key)


def start():
    _global.start()


def stop():
    _global.stop()
