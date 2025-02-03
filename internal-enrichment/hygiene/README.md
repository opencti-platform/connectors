# OpenCTI Hygiene Connector

This is an internal enrichment connector that uses the following external
projects to look for oberservable values in the database that you might want to
delete / decay because they are known to lead to false-positives when used for
detection:

* [misp-warninglists](https://github.com/MISP/misp-warninglists)

The connector works for the following OpenCTI observable types:

* IPv4-Addr
* IPv6-Addr
* Domain-Name
* StixFile
* Artifact

## Installation

Enabling this connector could be done by launching the Python process directly
after providing the correct configuration in the `config.yml` file or within a
Docker with the image `opencti/connector-hygiene:latest`.

We provide an example of [`docker-compose.yml`](docker-compose.yml) file that
could be used independently or integrated to the global `docker-compose.yml`
file of OpenCTI.

## Configuration

| Parameter            	      | Docker envvar                      | Mandatory | Default Value    | Description                                                                                                                                                                 |
|-----------------------------|------------------------------------| --------- |------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `warninglists_slow_search`  | `HYGIENE_WARNINGLISTS_SLOW_SEARCH` | No        | `false`          | Enable slow search mode for the warning lists. If true, uses the most appropriate search method. Can be slower. Default: exact match.                                       |
| --------------------------  | ---------------------------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enrich_subdomains`         | `HYGIENE_ENRICH_SUBDOMAINS`        | No        | `false`          | Enable enrichment of sub-domains, This option will add "hygiene_parent" label and ext refs of the parent domain to the subdomain, if sub-domain is not found but parent is. |
| `hygiene_label_name`        | `HYGIENE_LABEL_NAME`               | No        | `hygiene`        | Label name to be used when labeling matches, by default "hygiene".                                                                                                          |
| `hygiene_label_parent_name` | `HYGIENE_LABEL_PARENT_NAME`        | No        | `hygiene_parent` | Label name to be used when enriching sub-domains, by default "hygiene_parent".                                                                                              |
| `hygiene_label_color`       | `HYGIENE_LABEL_PARENT_NAME`        | No        | `#fc0341`        | Color to use for the label(s).                                                                                                                                              |

## Behavior

1. Adds a `hygiene` or `hygiene_parent` label on items that correspond to a warning list entry.
2. Adds an external reference for every matching warning list.
3. Sets the score of all related indicators to a value based on the number of
   reported entries (1:15, >=3:10, >=5:5, default:20).
