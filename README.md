# OpenCTI connectors

[![Website](https://img.shields.io/badge/website-opencti.io-blue.svg)](https://www.opencti.io)
[![CircleCI](https://circleci.com/gh/OpenCTI-Platform/connectors.svg?style=shield)](https://circleci.com/gh/OpenCTI-Platform/connectors/tree/master)
[![Slack Status](https://slack.luatix.org/badge.svg)](https://slack.luatix.org)

The following repository is used to store the OpenCTI connectors for the platform integration with other tools and applications. To know how to enable connectors on OpenCTI, please read the [dedicated documentation](https://opencti-platform.github.io/docs/installation/connectors).

## Connectors list and statuses

### External import connectors 

| Connector                               | Description                                   | Status                    | Last version                    |
| ----------------------------------------|-----------------------------------------------|---------------------------|---------------------------------|
| [AlienVault](alienvault)                | Import pulses from AlienVault                 | Production ready          | 3.0.3                           |
| [AMITT](amitt)                          | Import datasets of the AMITT framework        | Production ready          | 3.0.3                           |
| [CrowdStrike](crowdstrike)              | Import knowledge from CrowdStrike Falcon      | Production ready          | 3.0.3                           |
| [Cryptolaemus](cryptolaemus)            | Import Emotet C2 from the Cryptolaemus group  | In development            | -                               |
| [CVE](cve)                              | Import CVE vulnerabilities                    | Production ready          | 3.0.3                           |
| [COVID-19 CTC](cyber-threat-coalition)  | Import the COVID-19 CTC blacklist             | In development            | -                               |
| [Malpedia](malpedia)                    | Import the Malpedia malwares and indicators   | In development            | -                               |
| [MISP](misp)                            | Import MISP events                            | Production ready          | 3.0.3                           |
| [MITRE](mitre)                          | Import the MITRE ATT&CK / PRE-ATT&CK datasets | Production ready          | 3.0.3                           |
| [OpenCTI](opencti)                      | Import the OpenCTI datasets                   | Production ready          | 3.0.3                           |

### Internal import files connectors

| Connector                                               | Description                                   | Status                    | Last version                    |
| --------------------------------------------------------|-----------------------------------------------|---------------------------|---------------------------------|
| [ImportFilePdfObservables](import-file-pdf-observables) | Import observables from PDF files             | Production ready          | 3.0.3                           |
| [ImportFileStix](import-file-stix)                      | Import knwoledge from STIX 2.0 bundles        | Production ready          | 3.0.3                           |

### Internal enrichment connectors

| Connector                         | Description                                                 | Status                    | Last version                    |
| ----------------------------------|-------------------------------------------------------------|---------------------------|---------------------------------|
| [IpInfo](ipinfo)                  | Enrich IP addresses with geolocation                        | Production ready          | 3.0.3                           |
| [VirusTotal](virustotal)          | Enrich file hashes with corresponding hashes and file names | Production ready          | 3.0.3                           |

### Internal export files connectors

| Connector                                | Description                                   | Status                    | Last version                    |
| -----------------------------------------|-----------------------------------------------|---------------------------|---------------------------------|
| [ExportFileCSV](export-file-csv)         | Export entities in CSV                        | Production ready          | 3.0.3                           |
| [ExportFileSTIX](export-file-stix)       | Export entities in STIX 2.0 bundles           | Production ready          | 3.0.3                           |

## License

**Unless specified otherwise**, connectors are released under the [Apache 2.0](https://github.com/OpenCTI-Platform/connectors/blob/master/LICENSE). If a connector is released by its author under a different license, the subfolder corresponding to it will contain a *LICENSE* file.

## Contributing

We welcome your **[contributions for new connectors](https://opencti-platform.github.io/docs/development/connectors)**. Please feel free to fork the code, play with it, make some patches and send us pull requests using [issues](https://github.com/OpenCTI-Platform/connectors/issues).

## About

OpenCTI is a product powered by the collaboration of the [French national cybersecurity agency (ANSSI)](https://ssi.gouv.fr), the [CERT-EU](https://cert.europa.eu) and the [Luatix](https://www.luatix.org) non-profit organization.