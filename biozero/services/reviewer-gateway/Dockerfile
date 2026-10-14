FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /out/reviewer-gateway .

FROM alpine:3.23
WORKDIR /app
COPY --from=build /out/reviewer-gateway /app/reviewer-gateway
USER 1000:1000
EXPOSE 8083
ENTRYPOINT ["/app/reviewer-gateway"]
