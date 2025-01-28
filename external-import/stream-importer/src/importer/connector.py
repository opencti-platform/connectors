import base64
import json
import os
from collections import namedtuple

import pika
from minio import Minio
from minio.commonconfig import CopySource
from pika.exceptions import NackError, UnroutableError

from .lib.external_import import ExternalImportConnector
from .metrics import Metrics
from .utils import create_mq_ssl_context

Event = namedtuple("Event", "path entries")


class WrongFileOrder(Exception):
    """Exception raised when the file order is wrong."""

    def __init__(self, name: str, expected_file_number: int):
        super().__init__(
            f"File {name} is not in correct order, should be number {expected_file_number}."
        )


class StreamImporterConnector(ExternalImportConnector):
    """StreamImporterConnector read events from minio and sent them to RabbitMQ.

    The events are transformed to be sent to RabbitMQ for ingestion by OpenCTI.
    Once processed, the files are moved to another bucket.
    """

    def __init__(self):
        """Initialization of the connector"""
        super().__init__()

        self.metrics = Metrics(self.helper.connect_name)

        minio_endpoint = os.environ.get("MINIO_ENDPOINT")

        minio_port = os.environ.get("MINIO_PORT")
        self.minio_bucket = os.environ.get("MINIO_BUCKET")
        self.minio_folder = os.environ.get("MINIO_FOLDER")
        self.minio_bucket_done = os.environ.get("MINIO_BUCKET_DONE")
        minio_access_key = os.environ.get("MINIO_ACCESS_KEY")
        minio_secret_key = os.environ.get("MINIO_SECRET_KEY")
        minio_secure = str_to_bool(os.environ.get("MINIO_SECURE", default="true"))
        minio_cert_check = str_to_bool(
            os.environ.get("MINIO_CERT_CHECK", default="true")
        )
        self.perfect_sync = str_to_bool(os.environ.get("PERFECT_SYNC", default="false"))
        self.helper.log_info(f"Perfect synchronization: {self.perfect_sync}")

        self.helper.log_info(f"Minio endpoint: {minio_endpoint}:{minio_port}")
        self.helper.log_info(
            f"Bucket to fetch the stream: {self.minio_bucket}/{self.minio_folder}"
        )
        self.helper.log_info(f"Bucket to put processed files: {self.minio_bucket_done}")

        self.minio_client = Minio(
            f"{minio_endpoint}:{minio_port}",
            minio_access_key,
            minio_secret_key,
            secure=minio_secure,
            cert_check=minio_cert_check,
        )
        self.helper.log_info(f"Minio: {self.minio_client._base_url}")

        # Create the destination bucket if it does not exist.
        self.helper.log_info(
            f"Minio bucket to use: src={self.minio_bucket} / done={self.minio_bucket_done}"
        )
        if not self.minio_client.bucket_exists(self.minio_bucket_done):
            self.minio_client.make_bucket(self.minio_bucket_done)
            self.helper.log_info(f"Minio bucket {self.minio_bucket_done} created")

        self.helper.log_info("Stream importer connector initialized")

    def _collect_intelligence(self):
        """Collects intelligence from channels

        Collect files from minio, process them and send them to RabbitMQ.
        """
        self.helper.log_debug(
            f"{self.helper.connect_name} connector is starting the collection of objects..."
        )
        # Read objects from minio, each object contains multiple events.
        for obj in self.minio_client.list_objects(
            self.minio_bucket,
            start_after=self.minio_folder,
            recursive=True,
        ):
            self.metrics.read()
            file_number = int(obj.object_name.split("_")[-1].split(".")[0])
            state = self.helper.get_state() or {}
            expected_file_number = state.get("file_count", 0) + 1
            if expected_file_number != file_number:
                self.metrics.import_down()
                raise WrongFileOrder(obj.object_name, expected_file_number)
            try:
                response = self.minio_client.get_object(
                    obj.bucket_name,
                    obj.object_name,
                )
                # Read data from response
                self.send_event(Event(obj.object_name, response.data.decode()))

                # Update the state
                state["file_count"] = expected_file_number
                self.helper.set_state(state)
            except json.decoder.JSONDecodeError as e:
                self.metrics.import_down()
                self.helper.log_error(f"File {obj.object_name} is malformatted, not processing")
            finally:
                response.close()
                response.release_conn()

    def send_event(self, event: Event) -> None:
        """Send an event to RabbitMQ.

        Once the event is sent, the file is moved to another bucket.

        Parameters
        ----------
        event : tuple[Path, str]
            Event as a tuple with the first element being the path of the file and the second the content (not encoded).
        """
        self.helper.log_info(f"Processing events from {event.path}")
        pika_credentials = pika.PlainCredentials(
            self.helper.connector_config["connection"]["user"],
            self.helper.connector_config["connection"]["pass"],
        )
        pika_parameters = pika.ConnectionParameters(
            host=self.helper.connector_config["connection"]["host"],
            port=self.helper.connector_config["connection"]["port"],
            virtual_host=self.helper.connector_config["connection"]["vhost"],
            credentials=pika_credentials,
            ssl_options=(
                pika.SSLOptions(
                    create_mq_ssl_context(self.helper.config),
                    self.helper.connector_config["connection"]["host"],
                )
                if self.helper.connector_config["connection"]["use_ssl"]
                else None
            ),
        )
        pika_connection = pika.BlockingConnection(pika_parameters)
        channel = pika_connection.channel()
        try:
            channel.confirm_delivery()
        except Exception as err:  # pylint: disable=broad-except
            self.metrics.send_error()
            self.helper.connector_logger.warning(str(err))
            channel.close()
            pika_connection.close()
            return

        for e in event.entries.split("\n"):
            self._send_event(
                channel,
                e,
            )
            self.metrics.send()
        channel.close()
        pika_connection.close()

        # The event is processed, the file can be moved (well, copied and deleted...).
        self.minio_client.copy_object(
            self.minio_bucket_done,
            event.path,
            CopySource(self.minio_bucket, event.path),
        )
        self.minio_client.remove_object(self.minio_bucket, event.path)
        self.helper.log_info(f"File {event.path} moved to {self.minio_bucket_done}")

    def _send_event(self, channel, event: str) -> None:
        """Send the content of the event to RabbitMQ.

        Parameters
        ----------
        channel : pike.BlockingChannel
            Channel to send the event to.
        event : str
            Content of the event, as string.
        """
        if not event:
            self.helper.log_debug("Event is empty, skipping")
            return

        event_parsed = json.loads(event)
        self.helper.log_debug(f"Event parsed: {event_parsed}")

        message = {
            "type": "event",
            "synchronized": self.perfect_sync,
            "update": True,
            "previous_standard": event_parsed.get("previous_standard", None),
            "applicant_id": self.helper.applicant_id,
            "content": base64.b64encode(event.encode("utf-8")).decode("utf-8"),
        }

        self.helper.log_debug(f"Message to push: {json.dumps(message)}")

        # Send the message
        try:
            channel.basic_publish(
                exchange=self.helper.connector_config["push_exchange"],
                routing_key=self.helper.connector_config["push_routing"],
                body=json.dumps(message),
                properties=pika.BasicProperties(
                    delivery_mode=2, content_encoding="utf-8"  # make message persistent
                ),
            )
            self.helper.connector_logger.debug("Event has been sent")
            self.helper.metric.inc("bundle_send")
        except (UnroutableError, NackError):
            self.metrics.send_error()
            self.helper.connector_logger.error("Unable to send bundle, retry...")
            self._send_event(channel, event)


def str_to_bool(val):
    """Convert a string representation of truth to true or false.
    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    if val in ("n", "no", "f", "false", "off", "0"):
        return False
    raise ValueError(f"invalid truth value {val!r}")
