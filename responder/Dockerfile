FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends iptables nftables iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir kafka-python==2.0.2 redis==5.2.1 python-json-logger==2.0.7 pydantic==2.10.4 pydantic-settings==2.7.0

COPY responder.py /app/responder.py

CMD ["python", "-u", "/app/responder.py"]
