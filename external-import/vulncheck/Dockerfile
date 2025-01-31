FROM python:3.12.5-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Copy the connector
COPY src /opt/opencti-connector-vulncheck

# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
  apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/opencti-connector-vulncheck && \
  pip3 install --no-cache-dir -r requirements.txt && \
  apk del git build-base

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
