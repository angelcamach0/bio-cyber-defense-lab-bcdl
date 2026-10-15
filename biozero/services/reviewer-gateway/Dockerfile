FROM golang:1.26-alpine AS build
WORKDIR /src
# Build context is services/, with Dockerfile reviewer-gateway/Dockerfile.
# Copy only the sibling Go packages required by the selected executable.
COPY ownership-authority/go.mod ownership-authority/*.go ./ownership-authority/
COPY artifact-executor/go.mod artifact-executor/*.go ./artifact-executor/
COPY enclave-runner/go.mod ./enclave-runner/
COPY enclave-runner/receiptprojection/*.go ./enclave-runner/receiptprojection/
COPY enclave-runner/analysis/*.go ./enclave-runner/analysis/
COPY reviewer-gateway/go.mod reviewer-gateway/*.go ./reviewer-gateway/
WORKDIR /src/reviewer-gateway
RUN CGO_ENABLED=0 go build -o /out/reviewer-gateway .

FROM alpine:3.23
WORKDIR /app
COPY --from=build /out/reviewer-gateway /app/reviewer-gateway
USER 1000:1000
EXPOSE 8083
ENTRYPOINT ["/app/reviewer-gateway"]
