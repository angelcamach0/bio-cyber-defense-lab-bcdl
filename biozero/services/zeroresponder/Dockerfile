# ZeroResponder container: builds Go binary and runs as non-root user.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /out/zeroresponder ./main.go

FROM alpine:3.19
RUN adduser -D -g '' appuser
USER appuser
WORKDIR /app
COPY --from=build /out/zeroresponder /app/zeroresponder
EXPOSE 8090
ENTRYPOINT ["/app/zeroresponder"]
