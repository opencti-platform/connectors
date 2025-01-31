import ipaddress
from pathlib import Path
from typing import TYPE_CHECKING

from pycti import OpenCTIConnectorHelper
from spycloud_connector.models import opencti, spycloud
from spycloud_connector.services import ConfigLoader
from spycloud_connector.utils.decorators import handle_pydantic_validation_error
from spycloud_connector.utils.helpers import dict_to_markdown_table

if TYPE_CHECKING:
    from spycloud_connector.models.opencti import AuthorIdentityClass, IncidentSeverity
    from spycloud_connector.models.spycloud import BreachRecordSeverity


SEVERITY_LEVELS_BY_CODE: dict["BreachRecordSeverity", "IncidentSeverity"] = {
    2: "low",
    5: "medium",
    20: "high",
    25: "critical",
}


class ConverterToStix:
    """
    Provides methods to convert SpyCloud objects into OCTI objects following STIX 2.1 specification.
    """

    def __init__(self, helper: OpenCTIConnectorHelper, config: ConfigLoader):
        """
        Initialize ConverterToStix with necessary injections.
        :param helper: OpenCTIConnectorHelper instance
        :param config: ConfigLoader instance
        """
        self.helper = helper
        self.config = config
        self.author = ConverterToStix._create_author(
            name=self.helper.connect_name,
            identity_class="organization",
            description="SpyCloud external import connector",
        )
        self.tlp_marking = ConverterToStix._create_tlp_marking(
            level=self.config.spycloud.tlp_level
        )

    @staticmethod
    def _create_author(
        name: str, identity_class: "AuthorIdentityClass", description: str = None
    ) -> opencti.Author:
        """Create an OpenCTI Author."""
        return opencti.Author(
            name=name,
            identity_class=identity_class,
            description=description,
        )

    @staticmethod
    def _create_tlp_marking(level: opencti.TLPMarkingLevel) -> opencti.TLPMarking:
        """Create an OpenCTI TLP Marking."""
        return opencti.TLPMarking(level=level)

    @handle_pydantic_validation_error
    def create_incident(
        self,
        breach_record: spycloud.BreachRecord,
        breach_catalog: spycloud.BreachCatalog = None,
    ) -> opencti.Incident:
        """
        Create an Incident from given breach record and its catalog.
        :param breach_record: SpyCloud breach record
        :param breach_catalog: SpyCloud breach record's catalog
        :return: OpenCTI Incident
        """
        incident_source = breach_catalog.title or "Unknown"
        incident_severity = SEVERITY_LEVELS_BY_CODE[breach_record.severity]
        incident_name = (
            f"Spycloud {incident_severity} alert on "
            f"{breach_record.email or breach_record.username or breach_record.ip_addresses[0] or breach_record.document_id}"
        )
        incident_description = dict_to_markdown_table(
            breach_record.model_dump(
                exclude_none=True,
                exclude=[
                    "source_id",
                    "severity",
                    "spycloud_publish_date",
                ],
            )
        )

        incident = opencti.Incident(
            name=incident_name,
            description=incident_description,
            author=self.author,
            created_at=breach_record.spycloud_publish_date,
            markings=[self.tlp_marking],
            source=incident_source,
            severity=incident_severity,
            incident_type="data-breach",
            first_seen=breach_record.spycloud_publish_date,
        )
        return incident

    def create_observables(
        self, breach_record: spycloud.BreachRecord
    ) -> list[opencti.ObservableBaseModel]:
        """
        Create all found observables from given breach record.
        :param breach_record: SpyCloud breach record
        :return: OpenCTI observables
        """
        observables = []

        user_account = self._create_user_account(
            account_login=breach_record.user_hostname,
            account_type=breach_record.user_os,
        )
        if user_account:
            observables.append(user_account)

        user_account = self._create_user_account(account_login=breach_record.username)
        if user_account:
            observables.append(user_account)

        email_address = self._create_email_address(
            value=breach_record.email,
            display_name=breach_record.full_name,
            belongs_to_ref=user_account.id if user_account else None,
        )
        if email_address:
            observables.append(email_address)

        url = self._create_url(value=breach_record.target_url)
        if url:
            observables.append(url)

        domain_name = self._create_domain_name(value=breach_record.target_domain)
        if domain_name:
            observables.append(domain_name)

        domain_name = self._create_domain_name(value=breach_record.target_subdomain)
        if domain_name:
            observables.append(domain_name)

        mac_address = self._create_mac_address(value=breach_record.mac_address)
        if mac_address:
            observables.append(mac_address)

        user_agent = self._create_user_agent(value=breach_record.user_agent)
        if user_agent:
            observables.append(user_agent)

        if breach_record.ip_addresses:
            for ip_address_value in breach_record.ip_addresses:
                ip_address = self._create_ip_address(ip_address_value)
                if ip_address:
                    observables.append(ip_address)

        if breach_record.infected_path:
            file_path = Path(breach_record.infected_path)

            file = self._create_file(name=str(file_path))
            if file:
                observables.append(file)

            directory = self._create_directory(path=str(file_path.parent))
            if directory:
                observables.append(directory)

        return observables

    def create_related_to_relationship(
        self, source: opencti.ObservableBaseModel, target: opencti.Incident
    ) -> opencti.RelatedTo:
        """
        Create a relationship of type "related-to" between an observable and an Incident.
        :param source: Source (observable)
        :param target: Target (incident)
        :return: OpenCTI RelatedTo relationship
        """
        return opencti.RelatedTo(
            source=source,
            target=target,
            author=self.author,
            markings=[self.tlp_marking],
        )

    @handle_pydantic_validation_error
    def _create_directory(self, path: str) -> opencti.Directory | None:
        """Create an OpenCTI Directory observable."""
        if path:
            return opencti.Directory(
                path=path,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_domain_name(self, value: str) -> opencti.DomainName | None:
        """Create an OpenCTI DomainName observable."""
        if value:
            return opencti.DomainName(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_email_address(
        self, value: str, display_name: str = None, belongs_to_ref: str = None
    ) -> opencti.EmailAddress | None:
        """Create an OpenCTI EmailAddress observable."""
        if value:
            return opencti.EmailAddress(
                value=value,
                display_name=display_name,
                belongs_to_ref=belongs_to_ref,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_file(self, name: str) -> opencti.File | None:
        """Create an OpenCTI File observable."""
        if name:
            return opencti.File(
                name=name,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_ip_address(
        self, value: str
    ) -> opencti.IPv4Address | None | opencti.IPv6Address:
        """Create an OpenCTI IPv4Address or IPv6Address observable."""
        try:
            ip_address_version = ipaddress.ip_address(value).version
        except ValueError as e:
            self.helper.connector_logger.error(str(e))
            return None

        if ip_address_version == 4:
            return opencti.IPv4Address(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )
        if ip_address_version == 6:
            return opencti.IPv6Address(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_mac_address(self, value: str) -> opencti.MACAddress | None:
        """Create an OpenCTI MACAddress observable."""
        if value:
            return opencti.MACAddress(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_url(self, value: str) -> opencti.URL | None:
        """Create en OpenCTI URL observable."""
        if value:
            return opencti.URL(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_user_account(
        self, account_login: str = None, account_type: str = None
    ) -> opencti.UserAccount | None:
        """Create an OpenCTI UserAccount observable."""
        if account_login:
            return opencti.UserAccount(
                account_login=account_login,
                account_type=account_type,
                author=self.author,
                markings=[self.tlp_marking],
            )

    @handle_pydantic_validation_error
    def _create_user_agent(self, value: str) -> opencti.UserAgent | None:
        """Create an OpenCTI UserAgent observable."""
        if value:
            return opencti.UserAgent(
                value=value,
                author=self.author,
                markings=[self.tlp_marking],
            )
