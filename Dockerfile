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
RUN mkdir -p /data /runtime-tmp && chmod 1777 /runtime-tmp

# ---------- runtime stage ----------
FROM scratch

COPY --from=build /alertint /alertint
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# /data ships owned by the runtime user so named volumes mounted there
# (e.g. for the SQLite store) are writable without manual chown.
COPY --from=build --chown=65532:65532 /data /data
# SQLite migrations and some queries use temporary files. The image must
# provide /tmp even when no operator-supplied mount is present.
COPY --from=build --chmod=1777 /runtime-tmp /tmp

# Run as the conventional non-root UID (distroless "nonroot").
USER 65532:65532

EXPOSE 9911 9912
ENTRYPOINT ["/alertint"]
CMD ["serve", "--config", "/etc/alertint/config.yaml"]
