FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    scapy \
    flask \
    dnslib \
    requests

COPY analysis/traffic/ /app/traffic/
COPY analysis/ja3/ /app/ja3/
COPY analysis/rerouting/ /app/rerouting/
COPY sandbox/ /app/sandbox/
COPY intelligence/ /app/intelligence/
COPY analysis/*.py /app/
COPY scripts/auto_analyze.py /app/

# Create __init__.py files
RUN touch /app/__init__.py /app/traffic/__init__.py /app/ja3/__init__.py /app/rerouting/__init__.py /app/sandbox/__init__.py /app/intelligence/__init__.py

ENV PYTHONPATH=/app

CMD ["python3", "engine.py"]
