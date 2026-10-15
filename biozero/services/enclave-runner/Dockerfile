# Enclave runner container: builds Go binary and installs pipeline tools.
FROM golang:1.26-alpine AS build
WORKDIR /src/enclave-runner
# Build with biozero/services as context: the worker imports the local executor
# client and keeps that dependency separate from its own module.
COPY ownership-authority/ /src/ownership-authority/
COPY artifact-executor/ /src/artifact-executor/
COPY enclave-runner/ /src/enclave-runner/
RUN CGO_ENABLED=0 go build -o /out/enclave-runner .

FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 fastp minimap2 bcftools samtools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/enclave-runner /app/enclave-runner
ENTRYPOINT ["/app/enclave-runner"]
