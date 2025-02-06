# OpenCTI Splunk connector

This connector allows organizations to stream OpenCTI indicators to Infoblox Threat Defense (BloxOne). This will stream all active indicators to a custom list within Infoblox Threat Defense and remove any revoked indicators.

## Installation

### Requirements

- OpenCTI Platform >= 6.4.8

### Configuration

| Parameter                               | Docker envvar                           | Mandatory | Description                                                                                   |
|-----------------------------------------|-----------------------------------------| --------- |-----------------------------------------------------------------------------------------------|
| `opencti_url`                           | `OPENCTI_URL`                           | Yes       | The URL of the OpenCTI platform.                                                              |
| `opencti_token`                         | `OPENCTI_TOKEN`                         | Yes       | The default admin token configured in the OpenCTI platform parameters file.                   |
| `connector_id`                          | `CONNECTOR_ID`                          | Yes       | A valid arbitrary `UUIDv4` that must be unique for this connector.                            |
| `connector_type`                        | `CONNECTOR_TYPE`                        | Yes       | Type of connector                                                                             |
| `connector_live_stream_id`              | `CONNECTOR_LIVE_STREAM_ID`              | Yes       | The Live Stream ID of the stream created in the OpenCTI interface.                            |
| `connector_live_stream_listen_delete`   | `CONNECTOR_LIVE_STREAM_LISTEN_DELETE`   | Yes       | The Live Stream listen for delete.                                                            |
| `connector_live_stream_no_dependencies` | `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | Yes       | The Live Stream no dependencies.                                                              |
| `connector_name`                        | `CONNECTOR_NAME`                        | Yes       | Name of the connector. Defaulted to Infoblox Threat Defense                                   |
| `connector_scope`                       | `CONNECTOR_SCOPE`                       | Yes       | Must be `infoblox threat defense`.                                                            |
| `connector_confidence_level`            | `CONNECTOR_CONFIDENCE_LEVEL`            | Yes       | The default confidence level for created sightings (a number between 1 and 4).                |
| `connector_log_level`                   | `CONNECTOR_LOG_LEVEL`                   | Yes       | The log level for this connector, could be `debug`, `info`, `warn` or `error` (less verbose). |
| `infoblox_api_key`                      | `INFOBLOX_API_KEY`                      | Yes       | This is the API key you generated in the Infoblox Threat Defense console                      |
| `infoblox_verify_ssl`                   | `INFOBLOX_VERIFY_SSL`                   | Yes       | This is tell the connector to verify SSL or not.                                              |
| `infoblox_custom_list_id`               | `INFOBLOX_CUSTOM_LIST_ID`               | Yes       | This is the custom list id that OpenCTI will add/remove indicators from.                      |


### Usage

- This connector will stream your OpenCTI indicators to Infoblox Threat Defense (BloxOne).
- In order for this to function you will need to have an account setup in Infoblox Threat Defense with the correct API permissions.
- You will also need to add a custom list in your Infoblox platform and get the id assigned to it. Which can be aquired by performing the below and finding your specific list.
```
curl -X GET "https://csp.infoblox.com/api/atcfw/v1/named_lists" -H "Authorization: Token YOUR_API_TOKEN" -H "Content-Type: application/json"
```
- You will also need to setup a stream in OpenCTI that streams your domain-name based indicators.
- This connector will take care of adding valid indicators to Infoblox and removing revoked ones.
- Infoblox Public API Documentation: https://csp.infoblox.com/apidoc?url=https%3A%2F%2Fcsp.infoblox.com%2Fapidoc%2Fdocs%2FAtcfw#/named_lists/named_listsUpdateNamedList
