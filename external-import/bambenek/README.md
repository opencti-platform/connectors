# OpenCTI Bambenek CTI Connector

Table of Contents

- [OpenCTI Bambenek CTI connector](#opencti-bambenek-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
    - [Requirements](#requirements)
  - [Configuration variables](#configuration-variables)
    - [OpenCTI environment variables](#opencti-environment-variables)
    - [Base connector environment variables](#base-connector-environment-variables)
    - [Connector extra parameters environment variables](#connector-extra-parameters-environment-variables)
  - [Deployment](#deployment)
    - [Docker Deployment](#docker-deployment)
    - [Manual Deployment](#manual-deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Debugging](#debugging)
  - [Additional information](#additional-information)

## Introduction

The Bambenek connector ingests indicators of compromise (IOCs) from Bambenek Consulting Feeds.
The connector supports the ingestion of the following data collections: c2_dga,c2_dga_high_conf,c2_domain,c2_domain_highconf,c2_ip,c2_ip_highconf
- [c2_dga](https://osint.bambenekconsulting.com/manual/dga-feed.txt): Domain feed of known DGA domains from -2 to +3 days
- [c2_dga_high_conf](http://osint.bambenekconsulting.com/manual/dga-feed.txt): High confidence domain feed of known DGA domains from -2 to +3 days
- [c2_domain](http://osint.bambenekconsulting.com/manual/c2-dommasterlist.txt): Master feed of known, active and non-sinkholed C&Cs domain names
- [c2_domain_highconf](http://osint.bambenekconsulting.com/manual/c2-dommasterlist.txt): High confidence master feed of known, active and non-sinkholed C&Cs domain names
- [c2_ip](http://osint.bambenekconsulting.com/manual/c2-ipmasterlist.txt): Master feed of known, active and non-sinkholed C&Cs IP Addresses
- [c2_ip_highconf](http://osint.bambenekconsulting.com/manual/c2-ipmasterlist.txt): High confidence master feed of known, active and non-sinkholed C&Cs IP Addresses

## Documentation
For documentation please visit the links provided for the feed. A listing of all available feeds can be found [here](https://faf.bambenekconsulting.com/feeds/)
Information about Bambenek Consulting can be found [here](https://www.bambenekconsulting.com/)

The connector ingests the following entities:
- Indicators: Malicious Indicators are ingested as Indicators
- Observables: Some related information linked to the malicious IOC are ingested as observables and linked to the Indicator. Example: IP addresses associated with the malicious indicator (ip_info)


## Installation

### Requirements

- OpenCTI Platform >= 6.4.0

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or
in `config.yml` (for manual deployment).

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter       | config.yml | Docker environment variable | Default                                 | Mandatory | Description                                                                              |
|-----------------|------------|-----------------------------|-----------------------------------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /                                       | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Type  | type       | `CONNECTOR_TYPE`            | EXTERNAL_IMPORT                         | Yes       | Should always be set to `EXTERNAL_IMPORT` for this connector.                            |
| Connector Name  | name       | `CONNECTOR_NAME`            |                                         | Yes       | Name of the connector.                                                                   |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | ipv4-addr,ipv6-addr,domain,indicator    | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info                                    | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |

### Bambenek Connector extra parameters environment variables

Below are the parameters you'll need to set for the Bambenek connector.

| Parameter     | config.yml    | Docker environment variable    | Default                                                                   | Mandatory | Description                                                                                                                                                                                                           |
|---------------|---------------|--------------------------------|---------------------------------------------------------------------------|-----------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Client ID     | client_id     | BAMBENEK_USERNAME              |                                                                           | Yes       | Bambenek username                                                                                                                                                                                                     |
| Client Secret | client_secret | BAMBENEK_PASSWORD              |                                                                           | Yes       | Bambenek password                                                                                                                                                                                                     |
| Collections   | collections   | BAMBENEK_COLLECTIONS           | c2_dga,c2_dga_high_conf,c2_domain,c2_domain_highconf,c2_ip,c2_ip_highconf | Yes       | Bambenek data collections to fetch. Possibles values are: "2_dga,c2_dga_high_conf,c2_domain,c2_domain_highconf,c2_ip,c2_ip_highconf". Refer to the Bambenek documentation:  https://faf.bambenekconsulting.com/feeds/ |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.4.0`. If you don't, it will take the latest version, but
sometimes the OpenCTI SDK fails to initialize.

Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` with the appropriate configurations for your
environment. Then, start the docker container with the provided docker-compose.yml

```shell
docker compose up -d
# -d for detached
```

### Manual Deployment

Create a file `config.yml` based on the provided `config.yml.sample`.

Replace the configuration variables (especially the "**ChangeMe**" variables) with the appropriate configurations for
you environment.

Install the required python dependencies (preferably in a virtual environment):

```shell
pip3 install -r requirements.txt
```

Then, start the connector from recorded-future/src:

```shell
python3 main.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

The connector pulls files from Bambenek's server then parses them into stix2 objects depending on the feed


## Debugging

The connector can be debugged by setting the appropriate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.e., `self.helper.connector_logger.error("An error message")`.