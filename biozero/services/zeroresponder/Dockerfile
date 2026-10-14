# ZeroResponder container: builds Go binary and runs as non-root user.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/zeroresponder .

FROM alpine:3.23
RUN adduser -D -g '' appuser
USER appuser
WORKDIR /app
COPY --from=build /out/zeroresponder /app/zeroresponder
EXPOSE 8090
ENTRYPOINT ["/app/zeroresponder"]
