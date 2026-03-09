"""
Anomaly Detector — statistical scoring of incoming traffic.
Uses z-score analysis on rolling windows of request metrics.
Trains itself over time — the more normal traffic it sees, the more precise it becomes.
"""
import math
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Optional


class RollingStats:
    """Maintains a rolling window of values for z-score computation."""

    def __init__(self, window_size: int = 200):
        self.window_size = window_size
        self._values: deque = deque(maxlen=window_size)

    def add(self, value: float):
        self._values.append(value)

    @property
    def mean(self) -> float:
        if not self._values:
            return 0.0
        return sum(self._values) / len(self._values)

    @property
    def std(self) -> float:
        if len(self._values) < 2:
            return 1.0
        mean = self.mean
        variance = sum((v - mean) ** 2 for v in self._values) / len(self._values)
        return math.sqrt(variance) or 1.0

    def z_score(self, value: float) -> float:
        """How many standard deviations above the mean is this value?"""
        return (value - self.mean) / self.std

    def is_anomalous(self, value: float, threshold: float) -> bool:
        return self.z_score(value) > threshold

    @property
    def sample_count(self) -> int:
        return len(self._values)


class AnomalyDetector:
    """
    Per-IP anomaly detector using rolling statistics.
    Tracks request rates, response times, and error rates.
    """

    def __init__(self, z_threshold: float = 2.5):
        self.z_threshold = z_threshold
        # Stats per IP
        self._request_rate: dict[str, RollingStats] = defaultdict(lambda: RollingStats(100))
        self._response_time: dict[str, RollingStats] = defaultdict(lambda: RollingStats(100))
        self._error_rate: dict[str, RollingStats] = defaultdict(lambda: RollingStats(100))
        # Global stats for baseline
        self._global_request_rate = RollingStats(500)
        # Time windows: count requests per 10s window
        self._ip_window: dict[str, deque] = defaultdict(lambda: deque())
        self._window_seconds = 10

    def record_request(
        self,
        ip: str,
        response_time_ms: float,
        is_error: bool,
        timestamp: Optional[datetime] = None,
    ) -> dict:
        """
        Record a request and return anomaly scores.
        Returns dict with z-scores and whether each metric is anomalous.
        """
        now = timestamp or datetime.utcnow()

        # Update per-IP time window
        self._ip_window[ip].append(now)
        cutoff = now - timedelta(seconds=self._window_seconds)
        while self._ip_window[ip] and self._ip_window[ip][0] < cutoff:
            self._ip_window[ip].popleft()

        rate = len(self._ip_window[ip])

        # Update rolling stats
        self._request_rate[ip].add(float(rate))
        self._response_time[ip].add(response_time_ms)
        self._error_rate[ip].add(1.0 if is_error else 0.0)
        self._global_request_rate.add(float(rate))

        # Need enough samples before scoring
        if self._request_rate[ip].sample_count < 5:
            return {"anomalous": False, "reason": "insufficient_samples", "scores": {}}

        rate_z = self._request_rate[ip].z_score(rate)
        time_z = self._response_time[ip].z_score(response_time_ms)
        error_z = self._error_rate[ip].z_score(1.0 if is_error else 0.0)

        scores = {
            "request_rate_z": round(rate_z, 2),
            "response_time_z": round(time_z, 2),
            "error_rate_z": round(error_z, 2),
            "current_rate": rate,
            "mean_rate": round(self._request_rate[ip].mean, 2),
        }

        anomalies = []
        if rate_z > self.z_threshold:
            anomalies.append(f"request_rate_z={rate_z:.1f}")
        if error_z > self.z_threshold and is_error:
            anomalies.append(f"error_rate_z={error_z:.1f}")

        return {
            "anomalous": len(anomalies) > 0,
            "reason": ", ".join(anomalies),
            "scores": scores,
            "confidence": min(0.95, 0.5 + (max(rate_z, error_z) - self.z_threshold) * 0.1)
            if anomalies else 0.0,
        }

    def get_ip_profile(self, ip: str) -> dict:
        return {
            "ip": ip,
            "sample_count": self._request_rate[ip].sample_count,
            "mean_request_rate": round(self._request_rate[ip].mean, 2),
            "std_request_rate": round(self._request_rate[ip].std, 2),
            "mean_response_time": round(self._response_time[ip].mean, 2),
            "mean_error_rate": round(self._error_rate[ip].mean, 3),
        }


# Singleton instance
_detector = AnomalyDetector()


def get_detector() -> AnomalyDetector:
    return _detector
