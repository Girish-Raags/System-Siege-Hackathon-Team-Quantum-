FROM python:3.11-slim

WORKDIR /srv

# Build context is the project root (see docker-compose.yml), so paths
# below are relative to the repo root, preserving the same backend/app
# and frontend/ layout used in local development.
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY frontend ./frontend

ENV PYTHONUNBUFFERED=1
WORKDIR /srv/backend
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
