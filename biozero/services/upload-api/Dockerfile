# Upload API container: builds Go binary and runs as non-root user.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go admission.go securefiles.go streamupload.go ./
RUN CGO_ENABLED=0 go build -o /out/upload-api .

FROM alpine:3.23
RUN adduser -D -g '' appuser
USER appuser
WORKDIR /app
COPY --from=build /out/upload-api /app/upload-api
EXPOSE 8081
ENTRYPOINT ["/app/upload-api"]
