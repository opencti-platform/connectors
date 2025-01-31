# OpenCTI VulnCheck Connector

The VulnCheck Connector for OpenCTI is a standalone Python process designed to
integrate VulnCheck's extensive threat intelligence into the OpenCTI platform.
VulnCheck aggregates data from a wide range of sources, providing actionable
insights into vulnerabilities, exploits, ransomware activity, threat actors,
and more.

<!--toc:start-->
- [OpenCTI VulnCheck Connector](#opencti-vulncheck-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration](#configuration)
    - [OpenCTI Configuration](#opencti-configuration)
    - [VulnCheck Connector Configuration](#vulncheck-connector-configuration)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
    - [Data Sources](#data-sources)
    - [Data Volume](#data-volume)
  - [Debugging](#debugging)
  - [Useful Resources](#useful-resources)
  - [Maintainers](#maintainers)
<!--toc:end-->

## Introduction

The VulnCheck Connector retrieves and translates data from VulnCheck into STIX
objects. It supports feeds for Known Exploited Vulnerabilities (KEVs), NVD-2,
ransomware, threat actors, exploits, botnets, initial access indicators, and IP
intelligence. Each data source is processed to create structured, meaningful
objects like vulnerabilities, malware, infrastructure, and relationships.

The VulnCheck Connector helps organizations enrich their threat intelligence
within OpenCTI by automating the ingestion of curated vulnerability and threat
actor data. This enables:

- **Proactive Risk Management**: Identify and prioritize vulnerabilities
actively exploited in the wild, improving patch management and defensive
measures.
- **Threat Actor Profiling**: Gain insights into ransomware groups, botnets,
and advanced persistent threat (APT) groups with detailed metadata and
associated tactics.
- **Contextual Analysis**: Link vulnerabilities to threat actors, exploits, and
malicious infrastructure to build a comprehensive understanding of potential
threats.
- **Enhanced Situational Awareness**: Integrate multi-source threat
intelligence into a unified platform, enabling more informed decision-making
for security operations and incident response teams.

## Installation

### Requirements

- OpenCTI Platform >= 6.4.5
- A Valid [VulnCheck](https://www.vulncheck.com/) API Key

## Configuration

There are several configuration options, which can be set either in
`docker-compose.yml` (for Docker deployments) or in `config.yml` (for manual
deployments).

### OpenCTI Configuration

Below are the parameters you'll need to set for OpenCTI:

| Parameter         | config.yml | Docker Environment Variable | Mandatory | Description                                  |
|-------------------|------------|-----------------------------|-----------|----------------------------------------------|
| OpenCTI URL       | `url`      | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.            |
| OpenCTI Token     | `token`    | `OPENCTI_TOKEN`             | Yes       | The API token for authenticating with OpenCTI. |

### VulnCheck Connector Configuration

Below are the parameters you'll need to set for running the connector:

| Parameter       | config.yml     | Docker Environment Variable        | Default                                                                                                                | Mandatory | Description                                                                 |
|-----------------|----------------|------------------------------------|------------------------------------------------------------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------|
| Connector ID    | `id`           | `CONNECTOR_ID`                     | /                                                                                                                      | Yes       | A unique `UUIDv4` identifier for this connector.                            |
| Connector Type  | `type`         | `CONNECTOR_TYPE`                   | EXTERNAL_IMPORT                                                                                                        | Yes       | Specifies the type of connector. Should always be set to `EXTERNAL_IMPORT`. |
| Connector Name  | `name`         | `CONNECTOR_NAME`                   | VulnCheck                                                                                                              | Yes       | The name of the connector as it will appear in OpenCTI.                     |
| Connector Scope | `scope`        | `CONNECTOR_SCOPE`                  | VulnCheck                                                                                                              | Yes       | Must be set as `VulnCheck`                                                  |
| Log Level       | `log_level`    | `CONNECTOR_LOG_LEVEL`              | info                                                                                                                   | Yes       | Sets the verbosity of logs. Options: `debug`, `info`, `warn`, `error`.      |
| API Base URL    | `api_base_url` | `CONNECTOR_VULNCHECK_API_BASE_URL` | None                                                                                                                   | Yes       | The base URL for the VulnCheck API (e.g., `https://api.vulncheck.com/v3`).  |
| API Key         | `api_key`      | `CONNECTOR_VULNCHECK_API_KEY`      | None                                                                                                                   | Yes       | The API key for authenticating with VulnCheck's API.                        |
| Data Sources    | `data_sources` | `CONNECTOR_VULNCHECK_DATA_SOURCES` | botnets,epss,exploits,initial-access,ipintel,nist-nvd2,ransomware,snort,suricata,threat-actors,vulncheck-kev,vulncheck-nvd2 | Yes       | List of data sources to collect intelligence from.                          |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in
`requirements.txt` equal to whatever version of OpenCTI you're running.
Example, `pycti==5.12.20`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the
appropriate configurations for your environment. Then, start the docker
container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables)
with the appropriate configurations for you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from `vulncheck/src`:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use,
and should update automatically at a regular interval specified in your
`docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of
entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's
state and force a new download of data by re-running the connector.

> [!NOTE]
> The VulnCheck Connector is designed to fetch data once every 24 hours. This
> approach ensures the connector remains efficient and minimizes the risk of
> overloading the VulnCheck API or the OpenCTI platform.

## Behavior

The VulnCheck Connector integrates VulnCheck's threat intelligence data into
the OpenCTI platform, converting raw data from various feeds into structured
STIX objects. Below is an overview of its behavior and functionality:

### Data Sources

The connector retrieves data from VulnCheck's API and imports it into OpenCTI
as STIX objects. The following types of data are processed:

- **VulnCheck KEV**: Populates OpenCTI with vulnerabilities actively exploited
in the wild, focusing on high-priority risks.
- **NVD-2**: Imports vulnerability information enriched with CVSS scores,
descriptions, and associated CPEs. (VulnCheck NVD-2 is available for
subscribers, NIST NVD-2 is available for other users)
- **Exploits**: Maps exploits to vulnerabilities and generates corresponding
Malware objects in OpenCTI.
- **EPSS Enrichment**: Adds vulnerabilities along with their EPSS scores and
percentiles, helping prioritize remediation efforts based on exploit
probability.
- **Ransomware**: Creates Malware objects for ransomware families, linking them
to associated vulnerabilities.
- **Threat Actors**: Adds Threat Actor objects with external references,
relationships to targeted vulnerabilities, and descriptive metadata.
- **Botnets**: Ingests infrastructure data associated with botnet activities
and links them to targeted vulnerabilities.
- **Initial Access Indicators**: Maps CPEs and vulnerabilities leveraged for
initial access tactics.
- **IP Intelligence**: Adds infrastructure and IP-related intelligence,
including countries and related vulnerabilities.
- **Snort/Suricata Rules**: Ingests Snort and Suricata rules as Indicators.

### Data Volume

> [!WARNING]
> Users should be aware of the significant resource impact when enabling the
> `nist-nvd2` or `vulncheck-nvd2` data sources within the VulnCheck Connector.
>
> On the initial run, these feeds ingest every vulnerability available,
> creating a massive number of STIX Objects and Relationships (e.g., Software
> `has` Vulnerability).
>
> Subsequent runs will only pull vulnerabilities published on the previous day,
> significantly reducing the data volume after the initial ingestion. The first
> run requires substantial RAM and processing time due to the volume of data
> being processed. Please ensure your environment is prepared to support this
> before enabling the source.
>
> Sources can be also be disabled by removing them from the
> `CONNECTOR_VULNCHECK_DATA_SOURCES` variable in the [connector
> configuration](#vulncheck-connector-configuration).

To address this issue, set up two separate VulnCheck connectors, each dedicated
to specific data sources:

- Primary Connector:
  - Sources: `botnet`, `exploits`, `vulncheck-kev`, etc...
  - This connector will handle the main threat intelligence data without NVD
    data, ensuring timely ingestion and accurate updates.
- Secondary Connector:
  - Sources: `vulncheck-nvd2` or `nist-nvd2` only
  - This connector will handle NVD data independently, which allows it
    to manage the high data volume without interfering with the ingestion of
    other data sources.

## Debugging

The connector can be debugged by setting the appropiate log level. Note that
logging messages can be added using
`self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i. e.,
`self.helper.connector_logger.error("An error message")`.

---

## Useful Resources

OpenCTI documentation for connectors:

- [OpenCTI Ecosystem](https://filigran.notion.site/OpenCTI-Ecosystem-868329e9fb734fca89692b2ed6087e76)
- [Connectors Deployment](https://docs.opencti.io/latest/deployment/connectors/)
- [Connectors Development](https://docs.opencti.io/latest/development/connectors/)

## Maintainers

This integration is maintained by VulnCheck, the maintainers are:

- [@maddawik](https://github.com/maddawik) - Primary maintainer
