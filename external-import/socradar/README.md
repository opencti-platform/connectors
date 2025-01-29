# OpenCTI SOCRadar Connector

OpenCTI connector for importing threat intelligence feeds from SOCRadar platform.

## Description

This connector imports threat intelligence data from SOCRadar into OpenCTI. It processes various types of indicators including:
* IP addresses (IPv4 and IPv6)
* Domain names
* URLs
* File hashes (MD5, SHA1, SHA256)

## Configuration

| Parameter | Docker envvar | Mandatory | Description |
| --- | --- | --- | --- |
| `opencti.url` | `OPENCTI_URL` | Yes | The URL of your OpenCTI platform |
| `opencti.token` | `OPENCTI_TOKEN` | Yes | Your OpenCTI admin token |
| `radar.radar_base_feed_url` | `RADAR_BASE_FEED_URL` | Yes | SOCRadar API base URL |
| `radar.radar_socradar_key` | `RADAR_SOCRADAR_KEY` | Yes | Your SOCRadar API key |
| `radar.radar_run_interval` | `RADAR_RUN_INTERVAL` | Yes | Time between runs (in seconds, default: 600) |
| `radar.radar_collections_uuid` | `RADAR_COLLECTIONS_UUID` | Yes | Collection IDs to fetch |

The `radar_collections_uuid` parameter should contain the collection IDs you want to fetch from SOCRadar. Example configuration:

```yaml
radar_collections_uuid:
  collection_1:
    id: ["YOUR_COLLECTION_ID"]
    name: ["YOUR_COLLECTION_NAME"]
  collection_2:
    id: ["YOUR_COLLECTION_ID"]
    name: ["YOUR_COLLECTION_NAME"]
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/OpenCTI-Platform/connectors
cd connectors/external-import/socradar
```

2. Configure the connector:
```bash
cp src/config.yml.sample src/config.yml
```
Edit `src/config.yml` with your OpenCTI and SOCRadar configurations.

3. Add your connector to the `docker-compose.yml`:
```yaml
  connector-socradar:
    build: ./external-import/socradar
    container_name: docker-connector-socradar
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    restart: always
    depends_on:
      opencti:
        condition: service_healthy
```

4. Start with Docker:
```bash
docker-compose up -d connector-socradar
```

You can check the connector status and logs in the OpenCTI platform UI or using:
```bash
docker-compose logs -f connector-socradar
```
