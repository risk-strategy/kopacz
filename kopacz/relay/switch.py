"""
Relay switch — routes data between sessions.

Supports:
  - DNS↔DNS bridging  (restricted ↔ restricted)
  - Dead drop          (async message delivery)
  - Downstream queue   (server→client response buffer)
"""

import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, List, Optional, Tuple

MAX_DOWNSTREAM_QUEUE = 4096


class RelaySession:
    __slots__ = ("tag", "vid", "last_seen", "downstream")

    def __init__(self, tag: str, vid: int):
        self.tag = tag
        self.vid = vid
        self.last_seen = time.monotonic()
        self.downstream: Deque[bytes] = deque(maxlen=MAX_DOWNSTREAM_QUEUE)


class Switch:
    def __init__(self, dead_drop_max: int = 1000, dead_drop_ttl: float = 86400.0):
        self._sessions: Dict[str, RelaySession] = {}
        self._vid_map: Dict[int, str] = {}
        self._dead_drop: Dict[int, Deque[Tuple[int, bytes, float]]] = {}
        self._next_vid = 1000
        self._dd_max = dead_drop_max
        self._dd_ttl = dead_drop_ttl
        self._lock = threading.RLock()
        self._unregister_callbacks: List[Callable[[str], None]] = []

    def on_unregister(self, callback: Callable[[str], None]) -> None:
        """Register a callback invoked when a session tag is unregistered."""
        with self._lock:
            self._unregister_callbacks.append(callback)

    def register(self, tag: str) -> RelaySession:
        with self._lock:
            if tag in self._sessions:
                self._sessions[tag].last_seen = time.monotonic()
                return self._sessions[tag]
            vid = self._next_vid
            self._next_vid += 1
            sess = RelaySession(tag, vid)
            self._sessions[tag] = sess
            self._vid_map[vid] = tag
            return sess

    def unregister(self, tag: str) -> None:
        """Remove session and its VID mapping on session expiry/teardown, and notify apps."""
        with self._lock:
            sess = self._sessions.pop(tag, None)
            if sess is not None:
                self._vid_map.pop(sess.vid, None)
            callbacks = list(self._unregister_callbacks)
        for cb in callbacks:
            try:
                cb(tag)
            except Exception:
                pass

    def get(self, tag: str) -> Optional[RelaySession]:
        with self._lock:
            return self._sessions.get(tag)

    def has_pending(self, tag: str) -> bool:
        """Return True if session has queued downstream or dead-drop messages."""
        with self._lock:
            sess = self._sessions.get(tag)
            if sess is None:
                return False
            if sess.downstream:
                return True
            return bool(sess.vid in self._dead_drop and self._dead_drop[sess.vid])

    def enqueue_downstream(self, tag: str, data: bytes) -> bool:
        """Push data to a session's downstream queue."""
        with self._lock:
            sess = self._sessions.get(tag)
            if sess is None:
                return False
            sess.downstream.append(data)
            return True

    def poll_downstream(self, tag: str) -> Optional[bytes]:
        """Pop one downstream message for a session."""
        with self._lock:
            sess = self._sessions.get(tag)
            if sess is None:
                return None
            sess.last_seen = time.monotonic()
            if sess.downstream:
                return sess.downstream.popleft()
            # check dead drop
            if sess.vid in self._dead_drop and self._dead_drop[sess.vid]:
                _, payload, _ = self._dead_drop[sess.vid].popleft()
                return payload
            return None

    def route(self, from_vid: int, to_vid: int, payload: bytes) -> None:
        """Route payload to target VID, or dead-drop if offline."""
        with self._lock:
            if to_vid in self._vid_map:
                tag = self._vid_map[to_vid]
                if tag in self._sessions:
                    self._sessions[tag].downstream.append(payload)
            else:
                if to_vid not in self._dead_drop:
                    self._dead_drop[to_vid] = deque(maxlen=self._dd_max)
                self._dead_drop[to_vid].append((from_vid, payload, time.monotonic()))

    def cleanup(self) -> int:
        """Evict expired dead-drop entries. Returns count removed."""
        with self._lock:
            now = time.monotonic()
            removed = 0
            for vid in list(self._dead_drop):
                before = len(self._dead_drop[vid])
                self._dead_drop[vid] = deque(
                    (s, p, t) for s, p, t in self._dead_drop[vid] if now - t < self._dd_ttl
                )
                removed += before - len(self._dead_drop[vid])
                if not self._dead_drop[vid]:
                    del self._dead_drop[vid]
            return removed
