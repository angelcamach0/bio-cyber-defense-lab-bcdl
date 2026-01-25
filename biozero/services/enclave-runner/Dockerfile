# Enclave runner container: builds Go binary and installs pipeline tools.
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /out/enclave-runner ./main.go

FROM ubuntu:22.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 fastp minimap2 bcftools samtools ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /out/enclave-runner /app/enclave-runner
ENTRYPOINT ["/app/enclave-runner"]
