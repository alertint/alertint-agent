# syntax=docker/dockerfile:1

# ---------- build stage ----------
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /alertint ./cmd/alertint
RUN mkdir -p /data

# ---------- runtime stage ----------
FROM scratch

COPY --from=build /alertint /alertint
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# /data ships owned by the runtime user so named volumes mounted there
# (e.g. for the SQLite store) are writable without manual chown.
COPY --from=build --chown=65532:65532 /data /data

# Run as the conventional non-root UID (distroless "nonroot").
USER 65532:65532

EXPOSE 9911 9912
ENTRYPOINT ["/alertint"]
CMD ["serve", "--config", "/etc/alertint/config.yaml"]
