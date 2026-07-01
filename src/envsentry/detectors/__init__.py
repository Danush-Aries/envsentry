"""Detector registry: 12 provider (VERIFIED) detectors + 1 generic entropy (POSSIBLE)."""

from __future__ import annotations

from ..models import Detector
from .entropy import (
    DEFAULT_B64_THRESHOLD,
    DEFAULT_HEX_THRESHOLD,
    make_entropy_detector,
    shannon_entropy,
)
from .providers import PROVIDERS


def all_detectors(
    entropy_b64: float = DEFAULT_B64_THRESHOLD,
    entropy_hex: float = DEFAULT_HEX_THRESHOLD,
) -> list[Detector]:
    """Full ordered detector list. Providers first so VERIFIED wins de-dup ties."""
    return [*PROVIDERS, make_entropy_detector(entropy_b64, entropy_hex)]


# Default registry (default thresholds).
DETECTORS: list[Detector] = all_detectors()

__all__ = [
    "DETECTORS",
    "PROVIDERS",
    "all_detectors",
    "make_entropy_detector",
    "shannon_entropy",
]
