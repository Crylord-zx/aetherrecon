"""
Smart Rate Controller
-----------------------
Adaptive rate limiter with dynamic latency monitoring,
WAF detection, and fragile service protection.

Instead of fixed speeds:
- Dynamically adjust concurrency
- Watch latency and error rates
- Reduce errors automatically
- Gradually increase speed when stable
"""

import asyncio
import time


class RateLimiter:
    """Token-bucket rate limiter for async operations."""

    def __init__(self, rate: float = 10.0, burst: int = 20):
        self.rate = rate
        self.burst = burst
        self._tokens = float(burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Wait for and consume one rate-limit token."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait_time)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0

    async def __aenter__(self):
        await self.acquire()
        return self

    async def __aexit__(self, *exc):
        pass


class AdaptiveRateLimiter(RateLimiter):
    """
    Smart rate limiter that adapts based on response behavior.

    Features:
    - Starts at 25% of target rate (ramp-up)
    - Backs off on 429/403/503 responses
    - Monitors latency trends
    - WAF detection → aggressive backoff
    - Fragile service → safe mode
    - Gradually increases when stable
    """

    def __init__(self, rate: float = 10.0, burst: int = 20, backoff_factor: float = 2.0):
        start_rate = max(1.0, rate * 0.25)
        start_burst = max(1, int(burst * 0.25))
        super().__init__(start_rate, start_burst)
        self.target_rate = rate
        self.target_burst = burst
        self.backoff_factor = backoff_factor
        self._consecutive_errors = 0
        self._consecutive_successes = 0
        self._waf_detected = False
        self._total_requests = 0
        self._error_count = 0
        self._latencies: list[float] = []
        self._safe_mode = False

    async def report_success(self, latency: float = 0.0):
        """Report a successful request, gradually increasing rate."""
        async with self._lock:
            self._consecutive_errors = 0
            self._consecutive_successes += 1
            self._total_requests += 1

            if latency > 0:
                self._latencies.append(latency)
                self._latencies = self._latencies[-50:]  # Keep last 50

            # Check if latency is increasing → slow down
            if self._is_latency_increasing():
                self.rate = max(1.0, self.rate * 0.9)
                return

            # Increase rate for every 5 consecutive successes
            if self._consecutive_successes % 5 == 0 and self.rate < self.target_rate:
                self.rate = min(self.target_rate, self.rate * 1.2)
                self.burst = min(self.target_burst, int(self.burst * 1.2))

    async def report_throttle(self, reason: str = "429", latency: float = 0.0):
        """Report a rate-limit response or error, backing off."""
        async with self._lock:
            self._consecutive_errors += 1
            self._consecutive_successes = 0
            self._error_count += 1
            self._total_requests += 1

            # Sharp drop in rate
            self.rate = max(0.5, self.rate / self.backoff_factor)

            # WAF detection
            if reason == "403":
                self._waf_detected = True
                wait = min(120, 4 ** self._consecutive_errors)
            elif reason == "429":
                wait = min(60, 2 ** self._consecutive_errors)
            elif reason == "503":
                # Service overloaded — be very careful
                wait = min(90, 3 ** self._consecutive_errors)
                if self._consecutive_errors >= 3:
                    self._safe_mode = True
            else:
                wait = min(30, 2 ** self._consecutive_errors)

            await asyncio.sleep(wait)

    async def report_error(self, latency: float = 0.0):
        """Report a connection error (timeout, refused, etc.)."""
        async with self._lock:
            self._consecutive_errors += 1
            self._error_count += 1
            self._total_requests += 1

            # Slow down on errors
            self.rate = max(0.5, self.rate * 0.8)

            # If too many errors, enter safe mode
            if self._consecutive_errors >= 5:
                self._safe_mode = True
                self.rate = max(0.5, self.target_rate * 0.1)

    @property
    def waf_detected(self) -> bool:
        return self._waf_detected

    @property
    def is_safe_mode(self) -> bool:
        return self._safe_mode

    def _is_latency_increasing(self) -> bool:
        """Check if latency is trending upward."""
        if len(self._latencies) < 10:
            return False
        recent = self._latencies[-5:]
        older = self._latencies[-10:-5]
        avg_recent = sum(recent) / len(recent)
        avg_older = sum(older) / len(older)
        return avg_recent > avg_older * 1.5  # 50% increase threshold

    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        avg_latency = sum(self._latencies) / len(self._latencies) if self._latencies else 0
        return {
            "current_rate": round(self.rate, 2),
            "target_rate": self.target_rate,
            "total_requests": self._total_requests,
            "error_count": self._error_count,
            "error_rate": round(self._error_count / max(1, self._total_requests) * 100, 1),
            "avg_latency": round(avg_latency, 3),
            "waf_detected": self._waf_detected,
            "safe_mode": self._safe_mode,
            "consecutive_errors": self._consecutive_errors,
        }
