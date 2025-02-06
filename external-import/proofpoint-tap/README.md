# Proofpoint TAP Connector

The Proofpoint TAP connector for OpenCTI allows for the ingestion of phishing campaign data from Proofpoint TAP
into the OpenCTI platform. 

See : https://www.proofpoint.com/us/products/threat-defense


Table of Contents

- [Proofpoint TAP Connector](#proofpoint-tap-connector)
  - [Introduction](#introduction)
  - [Installation](#installation)
  - [Configuration variables](#configuration-variables)
  - [Deployment](#deployment)
  - [Usage](#usage)
  - [Behavior](#behavior)
  - [Development](#development)
  - [Additional information](#additional-information)

## Introduction
This connector fetches data such as campaign and their members, and integrates them 
into OpenCTI for further analysis and correlation with other threat intelligence data.

## Installation

### Requirements

- OpenCTI Platform >= 6.4
- Proofpoint TAP API access

## Configuration variables

The connector should be configured via environment variables.

For instance using `shell`


directly
```shell
export ENV_VAR_NAME="..."
```

with a .env file
```shell
export $(grep -v '^#' .env | xargs -d '\n')
```

or `docker-compose.yml` in the container `environment` section.

with a config.yaml file (dev purposes):

config.yaml should be composed of 2 levels keys/value such as
```yaml
connector: 
  id: "..."
```
you can then alter the `app.py` file to load the config.yaml using the dedicated adapter:

```python 
from proofpoint_tap.adapters.config import ConfigLoaderYaml

config = ConfigLoaderYaml("path/to/config.yaml")
```

### OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | Docker environment variable | Mandatory | Description                                          |
|---------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:
| Parameter       | Docker environment variable | Default         | Mandatory | Description                                                                              |
|-----------------|-----------------------------|-----------------|-----------|------------------------------------------------------------------------------------------|
| Connector ID    | `CONNECTOR_ID`              |                 | Yes       | A unique `UUIDv4` identifier for this connector instance.                                |
| Connector Name  | `CONNECTOR_NAME`            |                 | Yes       | Name of the connector.                                                                   |
| Connector Scope | `CONNECTOR_SCOPE`           |                 | Yes       | The scope or type of data the connector is importing, either a MIME type or Stix Object. |
| Log Level       | `CONNECTOR_LOG_LEVEL`       |                 | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.   |
| Duration Period | `CONNECTOR_DURATION_PERIOD` |                 | Yes       | The interval at which the connector runs, in ISO8601 format. Example: PT30M for 30 minutes. |
| Queue Threshold | `CONNECTOR_QUEUE_THRESHOLD` | 500 | No | The maximum size of the queue in MBytes. Default is 500MBytes. |
| Run and Terminate | `CONNECTOR_RUN_AND_TERMINATE` | False | No | If set to True, the connector will run once and then terminate. Default is False. |
| Send to Queue | `CONNECTOR_SEND_TO_QUEUE` | True | No | If set to True, the connector will send data to the queue. Default is True. |
| Send to Directory | `CONNECTOR_SEND_TO_DIRECTORY` | False | No | If set to True, the connector will send data to a directory. Default is False. |
| Directory Path | `CONNECTOR_SEND_TO_DIRECTORY_PATH` | CHANGEME | No | The path to the directory where data will be sent if `CONNECTOR_SEND_TO_DIRECTORY` is True. |
| Directory Retention | `CONNECTOR_SEND_TO_DIRECTORY_RETENTION` | 7 | No | The number of days to retain data in the directory. Default is 7 days. |


### Connector extra parameters environment variables

Below are the parameters you'll need to set for the connector:

| Parameter                              | Docker environment variable       | Default | Mandatory | Description                                                                                     |
|----------------------------------------|-----------------------------------|---------|-----------|-------------------------------------------------------------------------------------------------|
| API base URL                           | `TAP_API_BASE_URL`                |         | Yes       | Base URL for Proofpoint TAP API                                                        |
| API access key                         | `TAP_API_PRINCIPAL_KEY`           |         | Yes       | Access key for Proofpoint TAP  API                                                      |
| API secret key                         | `TAP_API_SECRET_KEY`              |         | Yes       | Secret key for Proofpoint TAP  API                                                      |
| API timeout                            | `TAP_API_TIMEOUT`                 |         | Yes       | Timeout for API requests in ISO8601                                                          |
| API backoff                            | `TAP_API_BACKOFF`                 |         | Yes       | Backoff time in ISO8601 for API retries                                                         |
| API retries                            | `TAP_API_RETRIES`                 |         | Yes       | Number of retries for API requests                                                              |
| Marking definition                     | `TAP_MARKING_DEFINITION`          |         | Yes       | Marking definition for exported data (Should be one of  "white", "green", "amber", "amber+strict", "red")                                                           |
| Export Campaigns                        | `TAP_EXPORT_CAMPAIGNS`           | False   | No        | Export campaigns to OpenCTI                                                  |
| Export Events                          | `TAP_EXPORT_EVENTS`               | False   | No        | Export events to OpenCTI                                                     |
| Events type                           | `TAP_EVENTS_TYPE  `                |         | No        | Events types to export (all, issues,messages_blocked,messages_delivered,clicks_blocked,clicks_permitted ) |


## Deployment

### Docker Deployment
Build a Docker Image using the provided `Dockerfile`.

Example:

```shell
# Replace the IMAGE NAME with the appropriate value
docker build . -t [IMAGE NAME]:latest
```

Make sure to replace the environment variables in `docker-compose.yml` or provide a `.env` file with the appropriate configurations for your
environment (see `.env.sample` file). Then, start the docker container with the provided `docker-compose.yml` file.

```shell
docker compose up -d
```

### Source code Deployment

Install the required package (preferably in a virtual environment):

```shell
python -m venv .venv
source .venv/bin/activate
pip install .
```

Then, start the connector:

```shell
python app.py
```

## Usage

After Installation, the connector should require minimal interaction to use, and should update automatically at a regular interval specified in your `docker-compose.yml` in `duration_period`.

However, if you would like to force an immediate download of a new batch of entities, navigate to:

`Data management` -> `Ingestion` -> `Connectors` in the OpenCTI platform.

Find the connector, and click on the refresh button to reset the connector's state and force a new
download of data by re-running the connector.

## Behavior
### Mapping details
The retrieved data are mapped as follows:
```mermaid
graph LR
    subgraph ProofpointTAP
        direction TB
        subgraph TAPCampaign[Campaign]
            TAPActors[Actors]
            TAPMalware[Malware]
            TAPTechniques[Techniques]
            TAPBrands[Brands]
            TAPCampaignMembers[CampaignMembers]
        end
    end

    subgraph OpenCTI
        direction LR
        subgraph OpenCTIReport[Report]
            subgraph DomainObjects
                direction TB
                
                OpenCTIIntrusionSet[Intrusion Set]
                OpenCTIMalware[Malware]
                OpenCTIAttackPattern[Attack Pattern]
                OpenCTITargetedOrganization[Targeted Organization]
            end
            subgraph Observables
            end
            subgraph Indicators
            end
        end
    end

    %% TAP Campaign generates OpenCTI entities
    TAPCampaign ==> OpenCTIReport
    TAPActors ==> |looping over each Actor| OpenCTIIntrusionSet
    TAPMalware ==> |looping over each Malware| OpenCTIMalware
    TAPTechniques ==> |looping over each Technique| OpenCTIAttackPattern
    TAPBrands ==> |looping over each Brand| OpenCTITargetedOrganization
    TAPCampaignMembers ==> |looping over each Member| Observables
    Observables ==> |looping over each observable| Indicators
    
    %% Relationships between entities

    OpenCTIIntrusionSet -.-> |"Uses"| OpenCTIMalware
    OpenCTIIntrusionSet -.-> |"Uses"| OpenCTIAttackPattern
    Indicators -.-> |"Indicates"| OpenCTIMalware
    Indicators -.-> |"Indicates"| OpenCTIIntrusionSet  
    Indicators -.-> |"Based on"| Observables
    OpenCTIIntrusionSet -.-> |"Targets"| OpenCTITargetedOrganization

```

```mermaid
graph LR
    subgraph ProofpointTAP
        direction TB
        subgraph TAPEvent[Event]
        end
    end

    subgraph OpenCTI
        direction LR
        subgraph DomainObjects
            direction TB
            OpenCTIIncident[Incident]
        end
        subgraph Observables
            OpenCTIEmailMessage[Email Message]
            OpenCTIEmailAddresses[Email Addresses]
        end
        
    end

    %% TAP Event generates OpenCTI entities
    TAPEvent ==> OpenCTIIncident
    TAPEvent ==> |looping over each recipients| OpenCTIEmailAddresses
    TAPEvent ==> |looping over each senders| OpenCTIEmailAddresses
    TAPEvent ==> OpenCTIEmailMessage
    
    %% Relationships between entities

    OpenCTIEmailAddresses -.-> |"Related to"| OpenCTIIncident
    OpenCTIEmailMessage -.-> |"Related to"| OpenCTIIncident

```

## Development
To develop on the connector source code, you can install the provided package in `editable` mode with the dev dependencies using :

```shell
pip install -e .[all]
``` 

### Linting and typing
To format, lint and validate the source code, you can use the isort, black, ruff and mypy configurations:

```shell
python -m isort . ; python -m black . --check ; python -m ruff check . ; python -m mypy . ; python -m pip_audit .
```

### Testing
To run the tests, you can use the following command:

```shell
python -m pytest -vv
```

## Additional information
N.A.