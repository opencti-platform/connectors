# OpenCTI URLScan Enrichment Connector

## Introduction

URLScan (https://urlscan.io/) is an online service that allows you to scan URLs to analyze and detect potential security threats. It provides a platform where users can submit links to be scanned to obtain information about the page's content, loaded external resources, potential threats, and other relevant security details.

## Requirements

- pycti

## Configuration variables

There are a number of configuration options, which are set either in `docker-compose.yml` (for Docker) or in `config.yml` (for manual deployment).

## OpenCTI environment variables

Below are the parameters you'll need to set for OpenCTI:

| Parameter     | config.yml | Docker environment variable | Mandatory | Description                                          |
|---------------|------------|-----------------------------|-----------|------------------------------------------------------|
| OpenCTI URL   | url        | `OPENCTI_URL`               | Yes       | The URL of the OpenCTI platform.                     |
| OpenCTI Token | token      | `OPENCTI_TOKEN`             | Yes       | The default admin token set in the OpenCTI platform. |

### Base connector environment variables

Below are the parameters you'll need to set for running the connector properly:

| Parameter         | config.yml        | Docker environment variable     | Default   | Mandatory | Description                                                                                      |
|-------------------|-------------------|---------------------------------|-----------|-----------|--------------------------------------------------------------------------------------------------|
| Connector ID      | id                | `CONNECTOR_ID`                  | /         | Yes       | A unique `UUIDv4` identifier for this connector instance.                                        |
| Connector Name    | name              | `CONNECTOR_NAME`                | `URLScan` | Yes       | Name of the connector.                                                                           |
| Connector Scope   | scope             | `CONNECTOR_SCOPE`               | /         | Yes       | Scope of the connector. Availables: `url or hostname or domain-name`, `ipv4-addr`, `ipv6-addr`   |
| Run and Terminate | run_and_terminate | `CONNECTOR_RUN_AND_TERMINATE`   | `False`   | No        | Launch the connector once if set to True. Takes 2 available values: `True` or `False`            |
| Log Level         | log_level         | `CONNECTOR_LOG_LEVEL`           | /         | Yes       | Determines the verbosity of the logs. Options are `debug`, `info`, `warn`, or `error`.           |

### URLScan Enrichment connector environment variables

Below are the parameters you'll need to set for URLScan Enrichment connector:

| Parameter                            | config.yml              | Docker environment variable                       | Default   | Mandatory  | Description                                                                                                             |
|--------------------------------------|-------------------------|---------------------------------------------------|-----------|------------|-------------------------------------------------------------------------------------------------------------------------|
| URLScan Enr. Api Key                 | api_key                 | `URLSCAN_ENRICHMENT_API_KEY`                      | /         | Yes        | URLScan API Key                                                                                                         |
| URLScan Enr. Api Base Url            | api_base_url            | `URLSCAN_ENRICHMENT_API_BASE_URL`                 | /         | Yes        | URLScan Base Url                                                                                                        |
| URLScan Enr. Import Screenshot       | import_screenshot       | `URLSCAN_ENRICHMENT_IMPORT_SCREENSHOT`            | `true`    | Yes        | Allows or not the import of the screenshot of the scan submitted in URLScan to OpenCTI.                                 |
| URLScan Enr. Visibility              | visibility              | `URLSCAN_ENRICHMENT_VISIBILITY`                   | `public`  | Yes        | URLScan offers several levels of visibility for submitted scans: `public`, `unlisted`, `private`                        |
| URLScan Enr. Search filtered by date | search_filtered_by_date | `URLSCAN_ENRICHMENT_SEARCH_FILTERED_BY_DATE`      | `>now-1y` | Yes        | Allows you to filter by date available: `>now-1h`, `>now-1d`, `>now-1y`, `[2022 TO 2023]`, `[2022/01/01 TO 2023/12/01]` |
| URLScan Enr. Max TLP                 | max_tlp                 | `URLSCAN_ENRICHMENT_MAX_TLP`                      | /         | Yes        | Do not send any data to URLScan if the TLP of the observable is greater than MAX_TLP                                    |
| URLScan Enr. Create Indicator        | create_indicator        | `URLSCAN_ENRICHMENT_CREATE_INDICATOR`             | `true`    | No         | Decide whether or not to create an indicator based on this observable


## Deployment

### Docker Deployment

Before building the Docker container, you need to set the version of pycti in `requirements.txt` equal to whatever version of OpenCTI you're running. Example, `pycti==6.1.3`. If you don't, it will take the latest version, but sometimes the OpenCTI SDK fails to initialize.

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

Then, start the connector from crowdstrike-endpoint-security/src:

```shell
python3 main.py
```

## Usage

After installation, the connector should require minimal interaction to use, and some configurations should be specified in your `docker-compose.yml` or `config.yml`.

## Warnings

- If you have the variable auto set to true, then it is important to choose the correct scope by selecting only one type of scope-submission (url or hostname or domain-name) to avoid looping ingestions.
    - This is an example of looping ingestion: you have set a scope submission of URL and Domain name. When you will search for URL, it will retrieve lots of entities, including some domain names. These domain names will then be searched too. However, they can bring you some URLs too, creating this infinite loop.

- If you enrich IPv4 and IPv6 observables, only a link to URLScan search in external reference (OpenCTI) will be generated, but you can play with the search period with the environment variable search_filtered_by_date to refine the search.

- While the analysis is still in progress, the Result API endpoint will respond with an HTTP status code of 404. The connector's polling logic is to wait 10 seconds and retry 12 times, for a maximum wait time of 2 minutes, until the analysis is complete or the maximum wait time is reached.
