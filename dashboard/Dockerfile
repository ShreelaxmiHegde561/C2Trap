# Dashboard Dockerfile (Build from project root)
FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic \
    requests

COPY dashboard/backend/ /app/backend/
COPY dashboard/frontend/ /app/frontend/
COPY intelligence/ /app/intelligence/
COPY analysis/detection/ /app/detection/

WORKDIR /app/backend

ENV PYTHONPATH=/app:/app/detection

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
