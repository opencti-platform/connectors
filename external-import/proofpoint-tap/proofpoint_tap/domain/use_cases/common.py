"""Offer common tools for use cases."""

from typing import Literal

from proofpoint_tap.domain.models.octi.common import TLPMarking
from proofpoint_tap.domain.models.octi.domain import OrganizationAuthor


class BaseUseCase:
    """Base use case class."""

    def __init__(
        self,
        tlp_marking_name: Literal["white", "green", "amber", "amber+strict", "red"],
    ):
        """Initialize the use case."""
        self.tlp_marking = TLPMarking(level=tlp_marking_name)
        self.author = OrganizationAuthor(
            name="ProofPoint TAP",
            description="Proofpoint Targeted Attack Protection (TAP) offers an innovative "
            "approach to detecting, analysing and blocking advanced threats that target the employees.",
            confidence=None,
            author=None,
            labels=None,
            markings=None,
            external_references=None,
            contact_information="https://www.proofpoint.com/us/contact",
            organization_type="vendor",
            reliability=None,
            aliases=None,
        )
