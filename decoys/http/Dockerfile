FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask gunicorn

COPY http_decoy.py .

EXPOSE 8888 8443

CMD ["gunicorn", "--bind", "0.0.0.0:8888", "--workers", "2", "--threads", "4", "http_decoy:app"]
