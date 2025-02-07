
# tpotce2OCTI Connector

## Overview
The `tpotce2OCTI` connector is designed to fetch threat intelligence from the Elasticsearch (ELK) stack of a T-Pot honeypot instance, then to ingest the gathered data into OpenCTI, transforming it into STIX2 format. The connector has an option available to download payloads fresh payloads followed by a static analysis (in the case where you do not have sandboxes), create notes with attacker commands, and establish relationships with observables and indicators.

The connector works for the following observable types:

- IPv4
- Url
- Location
- Asn
- Observed data
- File

## Prerequisites

- OpenCTI platform
- T-Pot honeypot with Elasticsearch (ELK) stack
- Docker or Python environment

## Features

- **Elasticsearch Integration**: Query Elasticsearch for threat intelligence data with support for pagination.
- **STIX2 Export**: Converts the collected data into STIX2 format, including observables, indicators, Location, ASNs, Notes and relationships.
- **Custom Identity and Marking**: Automatically assigns TLP marking and identity to STIX2 objects.
- **IP and URL Processing**: Extracts and processes IP addresses, URLs, and file hashes from bash scripts or commands let by attackers (optional).
- **Bash Script Analysis**: Handles and download malicious payloads in memory (not saved on your server) for additional network indicators. A proxy can be used to hide your infrastructure.
- **Fanging of Indicators**: Automatically fangs indicators such as IP addresses and URLs to make them safe for sharing.

## Requirements

- OpenCTI Platform >= 6.3.13 (not tested before this version and after)

### Environment Variables

Use the provided `sample.env` file to configure the connector. Below is an explanation of each configuration option:

| Variable                         | Description                                                        | Example                                    |
|:---------------------------------|:-------------------------------------------------------------------|:-------------------------------------------|
| OPENCTI_URL                      | URL of the OpenCTI instance.                                       | http://opencti:8080                        |
| OPENCTI_TOKEN                    | API token generated in OpenCTI for the connector.                  | fixme_uuidv4                               |
| CONNECTOR_ID                     | Unique identifier for this connector.                              | fixme_uuidv4                               |
| CONNECTOR_CONFIDENCE_LEVEL       | Confidence level for data ingested (0-100).                        | 80                                         |
| CONNECTOR_LOG_LEVEL              | Logging level for connector. Options: debug, info, warning, error. | info                                       |
| CONNECTOR_DURATION_PERIOD        | Frequency of connector execution in ISO 8601 duration format.      | PT60M                                      |
| CONNECTOR_UPDATE_EXISTING_DATA   | Whether to update existing data. True or False.                    | True                                       |
| CONNECTOR_SCOPE                  | Types of data this connector handles.                              | stix2,location,identity,marking-definition |
| CONNECTOR_NAME                   | Name of the connector instance.                                    | tpotce2OCTI                                |
| TPOTCE2OCTI_ELK_HOST             | URL for the Elasticsearch host.                                    | https://ip:64297/es                        |
| TPOTCE2OCTI_WEB_USER_RP          | Web username for reverse proxy authentication.                     | fixme_web_user                             |
| TPOTCE2OCTI_WEB_PASSWORD_RP      | Web password for reverse proxy authentication.                     | "fixme_password"                           |
| TPOTCE2OCTI_DOWNLOAD_PAYLOADS    | Whether to download payloads. Optional.                            | False                                      |
| TPOTCE2OCTI_CREATE_NOTES         | Whether to create notes for attacker commands linked to an entity. | True                                       |
| TPOTCE2OCTI_LIKELIHOOD_NOTES     | Likelihood score (0-100) for created notes.                        | 100                                        |
| TPOTCE2OCTI_PROXY_URL            | Proxy URL for outgoing requests (optional).                        | http://user:password@geo.iproyal.com:port  |
| TPOTCE2OCTI_CREATE_AUTHOR        | Name of the author for created STIX entities.                      | cti-intrinsec                              |
| TPOTCE2OCTI_MARKING              | Default marking for created entities.                              | TLP:GREEN                                  |
| TPOTCE2OCTI_CREATE_LABELS        | Labels to assign to created entities, separated by commas.         | "malicious-activity,honeypot,command,scan" |
| TPOTCE2OCTI_RETROFEED_START_DATE | Start date for retroactive feed processing in ISO 8601 format.     | 2024-12-03T18:07:29.890933Z                |

### Workflow processor
When `Tpotce2OCTI` encounters a URL parsed in an attacker's command (if the option is enabled in the configuration file) it will use the `DownloadManager` class to:
- Download the file from the URL and load it into memory in a temp file (neither written on disk nor executed).
- Calculate the file's hashes (including similarity hashes).
- Determine the MIME type and file size.
- Extract any additional indicators (like URLs or IPs) from the file's content if it is a bash script.
- Create corresponding STIX objects and relationships in OpenCTI for the downloaded file and the extracted indicators.

If the file downloaded is also a bash script the Workflow processor go to iteration 2 (till 5 then it stops as it is highly unlikely).

## How It Works

1. **Initialization**: The connector is initialized with configurations and environment variables.
2. **Data Collection**: It queries Elasticsearch for new or updated threat intelligence data capitalized by your Tpotce.
3. **Data Processing**: Extracts observables like IP addresses, URLs and file hashes (if this option is enabled), and creates corresponding STIX2 objects.
4. **STIX2 Bundling**: All processed data is bundled into a STIX2 bundle.
5. **Data Push**: The bundle is then sent to OpenCTI for further analysis.