FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir aiosmtpd

COPY smtp_decoy.py .

EXPOSE 25

CMD ["python", "smtp_decoy.py"]
