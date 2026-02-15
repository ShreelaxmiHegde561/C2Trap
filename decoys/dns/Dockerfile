FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir dnslib

COPY dns_decoy.py .

EXPOSE 53/udp 53/tcp

CMD ["python", "dns_decoy.py"]
