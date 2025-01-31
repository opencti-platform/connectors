# OpenCTI Internal Import YARA connector


Table of Contents

- [OpenCTI Internal Import YARA Connector](#opencti-internal-import-yara-connector)
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

This connector ingests YARA rules into OpenCTI, converting them into Indicators. 
As YARA files can contain one or multiple YARA rules, the connector can operate in two modes:
1. Single Indicator Mode: Combines all YARA rules contained in the .yar file into one STIX Indicator. (Split Rules option: False).
2. Split Indicator Mode: Creates individual STIX Indicators for each YARA rule contained in the .yar file. (1 flag per YARA rule) (Split Rules option: True).

### Supported formats

The connector only supports YAR files. Be sure to download files with the .yar extension so that they are taken into account by the connector.

**File input format**
- YAR file

## Installation

### Requirements

- OpenCTI Platform >= 6.0.0

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

| Parameter       | config.yml | Docker environment variable | Default         | Mandatory | Description                                                                                                                                       |
|-----------------|------------|-----------------------------|-----------------|-----------|---------------------------------------------------------------------------------------------------------------------------------------------------|
| Connector ID    | id         | `CONNECTOR_ID`              | /               | Yes       | A unique `UUIDv4` identifier for this connector instance.                                                                                         |
| Connector Name  | name       | `CONNECTOR_NAME`            | ImportFileYARA  | Yes       | Name of the connector.                                                                                                                            |
| Connector Scope | scope      | `CONNECTOR_SCOPE`           | text/yara+plain | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. <br/>This connector support only "text/yara+plain" file type. |
| Log Level       | log_level  | `CONNECTOR_LOG_LEVEL`       | info            | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.                                                            |

### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter   | config.yml   | Docker environment variable | Default | Mandatory | Description                                                                                       |
|-------------|--------------|-----------------------------|---------|-----------|---------------------------------------------------------------------------------------------------|
| Split Rules | split_rules | YARA_IMPORT_FILE_SPLIT_RULES | True    | No        | Indicates whether the YARA rules contained in a .yar file are to be imported individually or not. |

## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever
version of OpenCTI you're running. Example, `pycti==6.0.0`. If you don't, it will take the latest version, but
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

After Installation, the connector should require minimal interaction to use, and should update automatically at a
regular interval specified in your `docker-compose.yml` or `config.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior

<!--
Describe how the connector functions:
* What data is ingested, updated, or modified
* Important considerations for users when utilizing this connector
* Additional relevant details
-->

## Debugging

The connector can be debugged by setting the appropiate log level.
Note that logging messages can be added using `self.helper.connector_logger,{LOG_LEVEL}("Sample message")`, i.
e., `self.helper.connector_logger.error("An error message")`.

<!-- Any additional information to help future users debug and report detailed issues concerning this connector -->

## Additional information

The connector uses the “plyara” library to parse and extract YARA rules.