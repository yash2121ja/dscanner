# Docker image for running dscanner as a container
# Usage: docker run --rm -v /var/run/docker.sock:/var/run/docker.sock dscanner/dscanner scan nginx:latest

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    docker.io ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir .

ENTRYPOINT ["dscanner"]
CMD ["--help"]
