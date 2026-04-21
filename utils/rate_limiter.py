"""
VulnScanX - Token Bucket Rate Limiter
"""
import time
import threading


class RateLimiter:
    """
    Token bucket algorithm for precise rate limiting.
    Prevents overwhelming target servers and triggering WAFs.
    """
    def __init__(self, requests_per_second: int = 50):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.last_refill = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            refill = elapsed * self.rate
            self.tokens = min(self.rate, self.tokens + refill)
            self.last_refill = now
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1
