FROM python:3.11

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libmagic1 \
    libmagic-dev \
    file \
    && rm -rf /var/lib/apt/lists/*

# Copy the connector
COPY src /opt/opencti-connector-socradar/src/
COPY requirements.txt /opt/opencti-connector-socradar/

# Set the Python path
ENV PYTHONPATH="/opt/opencti-connector-socradar/src"

# Install Python packages
RUN pip3 install --no-cache-dir -r /opt/opencti-connector-socradar/requirements.txt

# Expose and entrypoint
COPY entrypoint.sh /
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
