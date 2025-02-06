"""Defin entities for OpenCTI."""

from proofpoint_tap.domain.models.octi.common import BaseEntity, TLPMarking
from proofpoint_tap.domain.models.octi.domain import OrganizationAuthor

__all__ = [
    # Common
    "BaseEntity",  # for typing prpose
    "TLPMarking",  # for application layer
    # Domain
    "OrganizationAuthor",  # for application layer
]
