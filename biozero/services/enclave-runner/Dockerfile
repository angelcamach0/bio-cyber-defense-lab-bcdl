# Enclave runner container: builds Go binary and installs pipeline tools.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go security_events.go ./
RUN CGO_ENABLED=0 go build -o /out/enclave-runner .

FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 fastp minimap2 bcftools samtools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/enclave-runner /app/enclave-runner
ENTRYPOINT ["/app/enclave-runner"]
