FROM python:3.12-slim

LABEL maintainer="AetherRecon"
LABEL description="Modular cybersecurity reconnaissance framework"

# Install system deps for DNS and crypto
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils whois curl git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["aetherrecon"]
CMD ["--help"]
