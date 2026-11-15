FROM python:3.12-slim

WORKDIR /app

# No build tools needed: all dependencies ship wheels for cp312.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY static/ ./static/

# Local SQLite history lives here (override with LINKBREAK_DB).
RUN mkdir -p /app/data

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
