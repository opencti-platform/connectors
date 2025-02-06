# OpenCTI ANY.RUN feed connector

Import TI feed from ANY.RUN Interactive Online Malware Sandbox

## Installation

The OpenCTI ANY.RUN TI Feed connector is a standalone Python process that must have access to the OpenCTI platform and the RabbitMQ. RabbitMQ credentials and connection parameters are provided by the API directly, as configured in the platform settings.

Enabling this connector could be done by launching the Python process directly after providing the correct configuration in the config.yml file or within a Docker with the image anyrun/opencti-connector-anyrun-feed:latest. We provide an example of docker-compose.yml file that could be used independently or integrated to the global docker-compose.yml file of OpenCTI.

If you are using it independently, remember that the connector will try to connect to the RabbitMQ on the port configured in the OpenCTI platform.

### Requirements

- OpenCTI Platform >= 5.12.32
- ANY.RUN TI Feed subscription

### Configuration


The connector can be configured with the following variables:


| Parameter             | Docker envvar         | Mandatory | Description                                                                                                                                                                   |
|-----------------------|-----------------------|-----------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `opencti_url`         | `OPENCTI_URL`         | Yes       | The URL of the OpenCTI platform. Note that final `/` should be avoided. Example value: `http://opencti:8080`                                                                  |
| `opencti_token`       | `OPENCTI_TOKEN`       | Yes       | The default admin token configured in the OpenCTI platform parameters file.                                                                                                   |
| `connector_id`        | `CONNECTOR_ID`        | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                                                                                                            |
| `connector_name`      | `CONNECTOR_NAME`      | Yes       | A connector name to be shown in OpenCTI.                                                                                                                                      |
| `connector_scope`     | `CONNECTOR_SCOPE`     | Yes       | Supported scope. E. g., `text/html`.                                                                                                                                          |
| `connector_log_level` | `CONNECTOR_LOG_LEVEL` | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose).                                                                                 |
| `interval`            | `CONNECTOR_RUN_EVERY` | Yes       | The time unit is represented by a single character at the end of the string: d for days, h for hours, m for minutes, and s for seconds. e.g., 30s is 30 seconds. 1d is 1 day. |
| `token`               | `ANYRUN_TI_TOKEN`     | Yes       | ANY.RUN TI Feed credentials (API-Token for demo-feed and Basic for full. Type will be selected automatically)                                                                 |
| `url`                 | `ANYRUN_TI_URL`       | No        | ANY.RUN TI Feed url                                                                                                                                                           |
