"""Define the Campaign port.

It provides only the necessary and sufficient methods to be injected in the use cases.
It should then be used by the adapter.
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


class ObservedDataPort(ABC):
    """Observed data port interface."""

    @property
    @abstractmethod
    def type_(self) -> str:
        """Get the observed data type."""
        pass

    @property
    @abstractmethod
    def value(self) -> str:
        """Get the observed data value."""
        pass

    @property
    @abstractmethod
    def observed_at(self) -> "datetime":
        """Get the observed data datetime."""
        pass


class CampaignPort(ABC):
    """Campaign port interface."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Get the name of the campaign."""
        pass

    @property
    @abstractmethod
    def start_datetime(self) -> "datetime":
        """Get the start datetime of the campaign."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Get the description of the campaign."""
        pass

    @property
    @abstractmethod
    def actor_names(self) -> list[str]:
        """Get the actor names of the campaign."""
        pass

    @property
    @abstractmethod
    def malware_names(self) -> list[str]:
        """Get the malware names of the campaign."""
        pass

    @property
    @abstractmethod
    def malware_family_names(self) -> list[str]:
        """Get the malware family names of the campaign."""
        pass

    @property
    @abstractmethod
    def targeted_brand_names(self) -> list[str]:
        """Get the targeted brand names of the campaign."""
        pass

    @property
    @abstractmethod
    def technique_names(self) -> list[str]:
        """Get the technique names of the campaign."""
        pass

    @property
    @abstractmethod
    def observed_data(self) -> list[ObservedDataPort]:
        """Get the observed data of the campaign."""
        pass


class CampaignsPort(ABC):
    """Campaigns port interface."""

    @abstractmethod
    def list(self, start_time: "datetime", stop_time: "datetime") -> list[str]:
        """Fetch the campaign ids."""
        pass

    @abstractmethod
    def details(self, campaign_id: str) -> CampaignPort:
        """Fetch the campaign details."""
        pass
