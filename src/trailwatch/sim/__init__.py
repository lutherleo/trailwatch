"""Synthetic CloudTrail account simulator with labeled incident injection."""

from trailwatch.sim.generator import (
    Incident,
    SimConfig,
    Simulation,
    SimulationError,
    delivered,
    write_dataset,
)
from trailwatch.sim.incidents import SCENARIOS

__all__ = [
    "SCENARIOS",
    "Incident",
    "SimConfig",
    "Simulation",
    "SimulationError",
    "delivered",
    "write_dataset",
]
