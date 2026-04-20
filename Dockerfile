FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/
COPY scripts/ scripts/

# Create log directory
RUN mkdir -p logs

EXPOSE 8080

# WARNING: This application is intentionally vulnerable.
# Never deploy to production or expose to untrusted networks.
# Binding to 0.0.0.0 inside container so Docker port-forwarding works.
# The docker run command should use -p 127.0.0.1:8080:8080 to restrict access.
CMD ["uvicorn", "src.app:app", "--host", "0.0.0.0", "--port", "8080"]
