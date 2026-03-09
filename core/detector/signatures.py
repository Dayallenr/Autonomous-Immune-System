"""
Signature Matcher — matches incoming events against known attack signatures
stored in the immunological memory DB.
"""
import re
from typing import Optional

from config.logging_config import setup_logging
from memory import store

logger = setup_logging("signature_matcher")


class SignatureMatcher:
    def __init__(self, cache_refresh_interval: int = 50):
        self._cache: list[dict] = []
        self._cache_refresh_interval = cache_refresh_interval
        self._calls_since_refresh = 0

    async def _refresh_cache(self):
        self._cache = await store.get_all_active_signatures()
        self._calls_since_refresh = 0
        logger.debug(f"[SignatureMatcher] Refreshed: {len(self._cache)} signatures")

    async def match(
        self, payload: str, event_type: Optional[str] = None
    ) -> tuple[bool, Optional[dict], float]:
        self._calls_since_refresh += 1
        if self._calls_since_refresh >= self._cache_refresh_interval or not self._cache:
            await self._refresh_cache()

        best_sig: Optional[dict] = None
        best_confidence = 0.0

        for sig in self._cache:
            try:
                if re.search(sig["pattern"], payload, re.IGNORECASE):
                    confidence = 1.0 - sig.get("detection_threshold", 0.7)
                    confidence = min(0.99, confidence + min(0.2, sig.get("hit_count", 1) * 0.01))
                    if confidence > best_confidence:
                        best_confidence = confidence
                        best_sig = sig
            except re.error:
                continue

        if best_sig:
            logger.info(
                f"[SignatureMatcher] HIT — {best_sig['attack_type']} "
                f"(confidence={best_confidence:.2f}, hits={best_sig.get('hit_count', 1)})"
            )

        return bool(best_sig), best_sig, best_confidence

    async def classify_event(self, event: dict) -> dict:
        payload = " ".join([
            str(event.get("payload_sample", "")),
            str(event.get("target_endpoint", "")),
            str(event.get("raw_data", "")),
        ])

        event_type = event.get("event_type")
        matched, sig, confidence = await self.match(payload, event_type)

        return {
            **event,
            "signature_matched": matched,
            "matched_signature_id": sig["id"] if sig else None,
            "matched_signature_type": sig["attack_type"] if sig else event_type,
            "signature_confidence": confidence,
            "known_attack": matched and confidence > 0.7,
            "final_confidence": max(event.get("confidence", 0.5), confidence) if matched else event.get("confidence", 0.5),
        }


_matcher = SignatureMatcher()


def get_matcher() -> SignatureMatcher:
    return _matcher
