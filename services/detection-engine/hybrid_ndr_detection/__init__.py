"""Local-only network detectors used by the Hybrid NDR MVP."""

from .engine import (
    DetectionEngine,
    DNSAnomalyDetector,
    NewDestinationDetector,
    PortScanDetector,
    SuricataAlertDetector,
    TrafficSpikeDetector,
)
from .service import (
    DetectionService,
    DetectionServiceConfig,
    ScheduledDetection,
    summarize_baseline_buckets,
)

__all__ = [
    "DetectionEngine",
    "DNSAnomalyDetector",
    "NewDestinationDetector",
    "PortScanDetector",
    "SuricataAlertDetector",
    "TrafficSpikeDetector",
    "DetectionService",
    "DetectionServiceConfig",
    "ScheduledDetection",
    "summarize_baseline_buckets",
]
