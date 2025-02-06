FROM python:3.13-alpine
ENV CONNECTOR_TYPE=STREAM

COPY src /opt/connector-sentinel-one-incident

RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev

RUN cd /opt/connector-sentinel-one-incident && \
    pip3 install --no-cache-dir -r requirements.txt && \
    apk del git build-base

COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
