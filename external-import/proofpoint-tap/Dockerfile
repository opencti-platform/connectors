FROM python:3.12-alpine AS base


# Install Python modules
# hadolint ignore=DL3003
RUN apk update && apk upgrade && \
    apk --no-cache add git build-base libmagic libffi-dev libxml2-dev libxslt-dev && \
    pip3 install --no-cache-dir --upgrade pip


FROM base AS package
# Copy the package
COPY proofpoint_tap /opt/proofpoint_tap
COPY pyproject.toml /opt/pyproject.toml

RUN cd /opt/ && \
    pip3 install --no-cache-dir . && \
    apk del git build-base && \
    rm /opt/pyproject.toml && \
    rm -rf /opt/proofpoint_tap

FROM package AS app
# Copy the app
COPY app.py /opt/app.py    

# Run the app
CMD ["python3", "/opt/app.py"]
