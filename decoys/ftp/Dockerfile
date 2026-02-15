FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir pyftpdlib

COPY ftp_decoy.py .

EXPOSE 21 30000-30009

CMD ["python", "ftp_decoy.py"]
