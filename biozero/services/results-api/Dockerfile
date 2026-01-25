# Results API container: builds Go binary and runs as non-root user.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN go build -o /out/results-api ./main.go

FROM alpine:3.23
RUN adduser -D -g '' appuser
USER appuser
WORKDIR /app
COPY --from=build /out/results-api /app/results-api
EXPOSE 8082
ENTRYPOINT ["/app/results-api"]
