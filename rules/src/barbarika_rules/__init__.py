"""Barbarika's normalized events and YAML detection-rule evaluator.

Live-detected CERT-In Annexure I categories: **4 of 20** (iii, iv, v, x). The
other 16 identifiers exist in :class:`CertInCategory` for schema completeness
only — that is representation, not detection coverage.
"""

from .engine import RuleMatch, evaluate_rule
from .rule import (
    CorrelationArm,
    CorrelationDetection,
    DetectionRule,
    EventPredicate,
    SequenceDetection,
    SequenceStep,
    SingleDetection,
    ThresholdDetection,
    load_rule,
)
from .schema import CertInCategory, NormalizedEvent

__all__ = [
    "CertInCategory",
    "CorrelationArm",
    "CorrelationDetection",
    "DetectionRule",
    "EventPredicate",
    "NormalizedEvent",
    "RuleMatch",
    "SequenceDetection",
    "SequenceStep",
    "SingleDetection",
    "ThresholdDetection",
    "evaluate_rule",
    "load_rule",
]
