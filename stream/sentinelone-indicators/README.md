# OpenCTI SentinelOne Indicator Stream Connector

This connector allows Indicators from an OpenCTI Instance to be uploaded to a SentinelOne account. 

<br>

This software is provided as a community-driven project and is not officially supported by SentinelOne. It is offered on an "as-is" basis, without warranties or guarantees, either express or implied. Users are encouraged to thoroughly test and validate the software before deploying it in their environments. While community contributions and feedback are welcome, SentinelOne does not provide formal technical support, maintenance, or updates for this project.

<br>


-This version of the connector simply uploads Indicators as they are created. 

<br>

## Implementation
After appending the container to your compose file, you will need to create a new user in your OpenCTI instance and retrieve some information for your SentinelOne Account in order to interface with it.

If you don't want to use the default stream, you will also need to create your own.

<br>
<br>

### Retrieving Your Account ID

![Account ID In S1](doc/account_id.png)


- Click on the settings icon at the bottom of the left panel on the console. 
- From the `Settings` menu, select `ACCOUNTS` and click on the account you seek to use in the below list.
- You will now be in the `Sentinels` menu. From here, select `ACCOUNT INFO` (you may need to scroll to the right on smaller monitors to see it).
- Underneath your account name you will see your account ID in the field `ACCOUNT ID`



<br>

### Generating an API Key

![Generating An API Token In S1](doc/api_generation.png)

- Click on your email address in the top right corner of the menu on the SentinelOne Console. 
- Click the `Actions` dropdown button and hover over `API Token Operations`.
- Click `Regenerate API token` and proceed with the required Authentication.
- **Note:** you do not need to include the `'APIToken '`component of the string in any configs

<br>

### Determining Your SentinelOne URL
Your SentinelOne URL is simply the first component of the URL you use to access the console.

![S1 URL Example](doc/url_finding.png)

When configuring the connector, ensure that you include the ending '/'. For example, for the above image, you would input `https://usea1-purple.sentinelone.net/`

<br>

### Creating the Connector User
It is best practice to create a new user under the `Connectors` group and to use its token to interface with your instance.

![Generating A User In OpenCTI](doc/user_creation.png)


- Locate the gear (Settings) icon on the left menu and click `Security`.
- On the menu on the right click on the `Users` option. 
- Click the blue `+` icon at the bottom of the list
- Enter `[C] S1 Indicator Connector`. **Note:** you can name this whatever you'd like, but you should include `[C]` at the start regardless.
- Enter the required information and ensure that under the `Groups` field `Connectors` is this selected option. 


<br>


### Creating a dedicated Stream (optional)


- To create a dedicated stream for this connector head to `Data sharing` -> `Live streams` in the OpenCTI platform.

![Creating a Stream in OpenCTI](doc/stream_creation.png)

- Give the stream a name so that it can be identified
- Optional filters can be applied to determine what kind of data goes into the connector. It is recommended to not set any filters as to allow SentinelOne to consume all types it can.
- Copy the streams ID to be you used in your environment variables. 


<br>

## Configuration

### **OpenCTI Parameters:**

| Parameter | config.yml  | Docker environment variable | Example                    | Description                                  |
|----------------------|------------|-----------------------------|----------------------------|----------------------------------------------|
| URL                 | `url`      | `OPENCTI_URL`               | `http://opencti:8080`    | The URL of your OpenCTI instance within its internal network.            |
| Token               | `token`    | `OPENCTI_TOKEN`             | `11111111-2222-3333-4444-555555555555`                 | The token of the user specifically created for this Connector, under the `Connectors` group.      |

---

<br>

### **Connector Parameters:**

| Parameter       | config.yml  | Docker environment variable | Example                                | Description                                                                            |
|------------------|------------|-----------------------------|----------------------------------------|----------------------------------------------------------------------------------------|
| ID              | `id`       | `CONNECTOR_ID`              | `11111111-2222-3333-4444-555555555555` | Unique `UUIDv4` identifier for the connector.                                          |
| Name            | `name`     | `CONNECTOR_NAME`            | `SentinelOne Indicator Export Stream`  | The Connector's name as it will appear in OpenCTI.                                     |
| Scope           | `scope`    | `CONNECTOR_SCOPE`           | `all`                                  | The scope of this connector.                                                           |
| Log Level       | `log_level`| `CONNECTOR_LOG_LEVEL`       | `info`                                 | The level of logs/outputs presented. `info` is recommended.                            |
| Live Stream ID | `live_stream_id`| `CONNECTOR_LIVE_STREAM_ID` | `live`  | The id of the stream to listen into, the default `live` is okay to use. |
| Stream Delete | `live_stream_listen_delete`| `CONNECTOR_LIVE_STREAM_LISTEN_DELETE` | `true`  | Whether or not the connector will delete Indicator creation events after processing them (stops repetition) |
| Stream No Dependencies | `live_stream_no_dependencies`| `CONNECTOR_LIVE_STREAM_NO_DEPENDENCIES` | `true`  | Determines whether the stream will require dependency on other entities, set to `true` |


---

<br>

### **SentinelOne Parameters**

| Parameter                 | config.yml           | Docker environment variable     | Example                                  | Description                                                                 |
|---------------------------|----------------------|---------------------------------|------------------------------------------|-----------------------------------------------------------------------------|
| SentinelOne URL       | `url`               | `SENTINELONE_URL`              | `https://usea1-purple.sentinelone.net/` | The SentinelOne platform URL. **NOTE:** The URL should end with a `/`.      |
| SentinelOne API Key  | `api_key`           | `SENTINELONE_API_KEY`          | `eyJraWQiO...`                          | The API key for your SentinelOne account (JWT). **NOTE:** Should not include `APIToken`. |
| SentinelOne Account ID| `account_id`        | `SENTINELONE_ACCOUNT_ID`       | `1234567890123456789`                    | The ID of your SentinelOne Account.                                         |
| Max API Call Attempts | `max_api_attempts`  | `SENTINELONE_MAX_API_ATTEMPTS` | `5`                                      | The maximum number of retry attempts when API requests to SentinelOne repeatedly fail. `5` is recommended. |
---

<br>