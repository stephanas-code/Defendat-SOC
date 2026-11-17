FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --default-timeout=100 --retries 10 -r /app/requirements.txt

COPY sensor /app/sensor

CMD ["python", "-u", "-m", "sensor.sensor"]
