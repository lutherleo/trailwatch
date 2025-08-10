"""trailwatch: streaming CloudTrail identity-threat detection.

Public API::

    from trailwatch import Config, Detector, parse_record

    detector = Detector(Config())
    for alert in detector.run(events):
        ...
"""

from trailwatch.config import Config
from trailwatch.engine import Detector
from trailwatch.model import Alert, Event, Finding, Severity
from trailwatch.parse import ParseError, parse_record

__version__ = "0.1.0"

__all__ = [
    "Alert",
    "Config",
    "Detector",
    "Event",
    "Finding",
    "ParseError",
    "Severity",
    "__version__",
    "parse_record",
]
