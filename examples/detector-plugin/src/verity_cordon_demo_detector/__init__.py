"""Local reference detector plugin for Verity Cordon."""

from verity_cordon_demo_detector.detector import (
    DETECTOR_ID,
    DETECTOR_VERSION,
    SyntheticDemoSinkDetector,
    create_detector,
)

__all__ = [
    "DETECTOR_ID",
    "DETECTOR_VERSION",
    "SyntheticDemoSinkDetector",
    "create_detector",
]
