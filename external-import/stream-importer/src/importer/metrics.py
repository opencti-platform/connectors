from prometheus_client import Counter, Gauge


class Metrics:
    """Metrics for the connector.

    The http server is already started by the OpenCTI connector helper.
    """

    def __init__(self, name: str):
        self.name = name

        self._sent_messages_total = Counter(
            "sent_messages_total", "Number of messages sent to RabbitMQ", ["name"]
        )
        self._sent_errors_total = Counter(
            "sent_errors_total",
            "Number of errors sending messages to RabbitMQ",
            ["name"],
        )

        self._read_files_total = Counter(
            "read_files_total", "Number of files read from minio", ["name"]
        )
        self._import_up = Gauge(
            "import_up",
            "Set to 1 if import is successfully running, 0 in case of issues (either incorrect file number or malformatted data)",
            ["name"],
        )

    def send(self):
        self._sent_messages_total.labels(self.name).inc()
        self._import_up.labels(self.name).set(1.0)

    def send_error(self):
        self._sent_errors_total.labels(self.name).inc()

    def read(self):
        self._read_files_total.labels(self.name).inc()

    def import_down(self):
        self._import_up.labels(self.name).set(0.0)
