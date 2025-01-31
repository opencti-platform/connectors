FROM python:3.13-alpine
ENV CONNECTOR_TYPE=STREAM

COPY src /opt/connector-sentinel-one-indicator


RUN apk --no-cache add file libmagic \
    libxml2 libxml2-dev libxslt libxslt-dev yaml-dev

RUN cd /opt/connector-sentinel-one-indicator && \
    pip3 install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
