FROM python:3.12-alpine
ENV CONNECTOR_TYPE=INTERNAL_IMPORT_FILE

# Copy the connector
COPY src /opt/opencti-connector-import-file-yara

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev gfortran musl-dev g++ openblas openblas-dev && \
    cd /opt/opencti-connector-import-file-yara && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base gfortran musl-dev g++ openblas-dev

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh && chown -R :root /opt/opencti-connector-import-file-yara && chmod -R g+rwX /opt/opencti-connector-import-file-yara
WORKDIR /opt/opencti-connector-import-file-yara
ENV HOME=/opt/opencti-connector-import-file-yara
ENTRYPOINT ["/entrypoint.sh"]
