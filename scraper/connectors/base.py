"""Collector interface for pluggable source connectors."""

from abc import ABC, abstractmethod


class Collector(ABC):
    """Interface for external collectors.

    Implementations must enforce source-specific legal, policy, and ToS compliance.
    """

    @abstractmethod
    def run(self, frequency_snapshot=None):
        """Run the collector and return number of new alerts."""
        raise NotImplementedError
