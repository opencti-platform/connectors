"""Offer tools to ingest Incidents and related entities from Proofpoint TAP Events."""

from proofpoint_tap.domain.models.octi.common import BaseEntity
from proofpoint_tap.domain.models.octi.domain import Incident
from proofpoint_tap.domain.models.octi.observables import EmailAddress, EmailMessage
from proofpoint_tap.domain.models.octi.relationships import (
    EmailAddressRelatedToIncident,
    EmailMessageRelatedToIncident,
)
from proofpoint_tap.domain.use_cases.common import BaseUseCase
from proofpoint_tap.ports.event import ClickEventPort, EventPort, MessageEventPort


class IncidentProcessor(BaseUseCase):
    """Process incident and related entities."""

    def make_incident(self, event: EventPort) -> Incident:
        """Make incident from event."""
        return Incident(
            name=f"[{event.type}] - {event.guid}",
            incident_type=None,
            severity=None,
            description=event.to_markdown_table(),
            source=None,
            author=self.author,
            labels=None,
            markings=[self.tlp_marking],
            external_references=None,
            first_seen=event.time,
            last_seen=None,
            objective=None,
        )

    def make_emails_from_click_event(
        self, click_event: ClickEventPort
    ) -> list[EmailAddress]:
        """Make email addresses from event."""
        sender = EmailAddress(
            score=None,
            description=None,
            labels=None,
            external_references=None,
            markings=None,
            author=self.author,
            value=click_event.sender_address,
            display_name=None,
        )

        recipients = [
            EmailAddress(
                score=None,
                description=None,
                labels=None,
                external_references=None,
                markings=None,
                author=self.author,
                value=recipient,
                display_name=None,
            )
            for recipient in (click_event.recipients or [])
        ]

        return [sender] + recipients

    def make_emails_from_message_event(
        self, message_event: MessageEventPort
    ) -> tuple[EmailMessage, list[EmailAddress]]:
        """Make email message and addresses from message event."""
        sender = EmailAddress(
            score=None,
            description=None,
            labels=None,
            external_references=None,
            markings=None,
            author=self.author,
            value=message_event.sender_address,
            display_name=None,
        )
        recipients = [
            EmailAddress(
                score=None,
                description=None,
                labels=None,
                external_references=None,
                markings=None,
                author=self.author,
                value=recipient,
                display_name=None,
            )
            for recipient in (message_event.recipients or [])
        ]
        from_ = [
            EmailAddress(
                score=None,
                description=None,
                labels=None,
                external_references=None,
                markings=None,
                author=self.author,
                value=from_address,
                display_name=None,
            )
            for from_address in (message_event.from_addresses or [])
        ]
        to_ = [
            EmailAddress(
                score=None,
                description=None,
                labels=None,
                external_references=None,
                markings=None,
                author=self.author,
                value=to,
                display_name=None,
            )
            for to in (message_event.to_addresses or [])
        ]
        cc = [
            EmailAddress(
                score=None,
                description=None,
                labels=None,
                external_references=None,
                markings=None,
                author=self.author,
                value=cc,
                display_name=None,
            )
            for cc in (message_event.cc_addresses or [])
        ]
        message = EmailMessage(
            score=None,
            description=None,
            labels=None,
            external_references=None,
            markings=[self.tlp_marking],
            author=self.author,
            attribute_date=message_event.time,
            body=None,
            content_type=None,
            is_multipart=False,
            message_id=message_event.id,
            received_lines=None,
            subject=message_event.subject or "",
            from_=sender,
            to_=recipients,
            cc_=cc,
            bcc_=None,
        )

        return message, [sender] + from_ + to_ + recipients + cc

    def make_email_address_related_to_incident(
        self, email_address: EmailAddress, incident: Incident
    ) -> EmailAddressRelatedToIncident:
        """Make email address related to incident."""
        return EmailAddressRelatedToIncident(
            source=email_address,
            target=incident,
            start_time=incident.first_seen,
            author=self.author,
            markings=[self.tlp_marking],
            created=None,
            modified=None,
            description=None,
            stop_time=None,
            confidence=None,
            external_references=None,
        )

    def make_email_message_related_to_incident(
        self, email_message: EmailMessage, incident: Incident
    ) -> EmailMessageRelatedToIncident:
        """Make email message related to incident."""
        return EmailMessageRelatedToIncident(
            source=email_message,
            target=incident,
            start_time=incident.first_seen,
            author=self.author,
            markings=[self.tlp_marking],
            created=None,
            modified=None,
            description=None,
            stop_time=None,
            confidence=None,
            external_references=None,
        )

    def run_on_event(self, event: EventPort) -> list[BaseEntity]:
        """Run the use case on an event."""
        entities: list[BaseEntity] = []  # result holder
        # create incident
        incident = self.make_incident(event)
        entities.append(incident)

        # create emails
        if isinstance(event, ClickEventPort):
            emails = self.make_emails_from_click_event(event)
        elif isinstance(event, MessageEventPort):
            message, emails = self.make_emails_from_message_event(event)
            email_message_related_to_incident = (
                self.make_email_message_related_to_incident(message, incident)
            )
            entities.append(message)
            entities.append(email_message_related_to_incident)
        else:
            raise ValueError(f"Event type {type(event)} not supported.")
        entities.extend(emails)

        email_addresses_related_to_incident = [
            self.make_email_address_related_to_incident(email, incident)
            for email in emails
        ]

        entities.extend(email_addresses_related_to_incident)

        if entities:
            entities.append(self.author)
            entities.append(self.tlp_marking)
        return entities
