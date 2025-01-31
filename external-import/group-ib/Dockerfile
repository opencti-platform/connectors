FROM python:3.12-alpine
ENV CONNECTOR_TYPE=EXTERNAL_IMPORT

# Install Python modules
# hadolint ignore=DL3003
RUN apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt
RUN rm -rf /var/cache/apk/*

# Copy the connector
COPY src /opt/connector/src
COPY docs /opt/connector/docs
WORKDIR /opt/connector/src
COPY .env /opt/connector/src/

# Install TI API lib
RUN pip3 install /opt/connector/src/lib/cyberintegrations-0.6.6-py3-none-any.whl

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
