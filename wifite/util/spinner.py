import sys
import time
import threading


_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
_DONE   = '✔'
_FAIL   = '✘'


class Spinner:
    def __init__(self, message='', color_code='\033[96m'):
        self._message    = message
        self._color      = color_code
        self._reset      = '\033[0m'
        self._green      = '\033[92m'
        self._red        = '\033[91m'
        self._dim        = '\033[2m'
        self._running    = False
        self._thread     = None
        self._frame_idx  = 0
        self._lock       = threading.Lock()
        self._suffix     = ''

    def _spin(self):
        while self._running:
            with self._lock:
                frame = _FRAMES[self._frame_idx % len(_FRAMES)]
                self._frame_idx += 1
                suffix = self._suffix
                msg = self._message
            line = '\r  %s%s%s  %s%s%s' % (
                self._color, frame, self._reset,
                self._dim, msg, self._reset
            )
            if suffix:
                line += '  %s%s%s' % (self._dim, suffix, self._reset)
            sys.stderr.write(line)
            sys.stderr.flush()
            time.sleep(0.08)

    def set_suffix(self, text):
        with self._lock:
            self._suffix = text

    def set_message(self, text):
        with self._lock:
            self._message = text

    def start(self):
        self._running = True
        self._thread  = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()
        return self

    def stop(self, success=True, final_msg=None):
        self._running = False
        if self._thread:
            self._thread.join()
        icon  = self._green + _DONE + self._reset if success else self._red + _FAIL + self._reset
        label = final_msg or self._message
        sys.stderr.write('\r  %s  %s\n' % (icon, label))
        sys.stderr.flush()

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, *_):
        self.stop(success=exc_type is None)
