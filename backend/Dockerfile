# CloudSentinel API — container for ECS Fargate.
FROM python:3.12-slim

WORKDIR /app

# Install deps first (layer caching).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code.
COPY app/ ./app/

# Fargate task listens on 8000; ALB target group forwards here.
EXPOSE 8000

# Uvicorn bound to 0.0.0.0 so the container is reachable.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
