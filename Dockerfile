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

# ---------- runtime stage ----------
FROM scratch

COPY --from=build /alertint /alertint
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 9911 9912
ENTRYPOINT ["/alertint"]
CMD ["serve", "--config", "/etc/alertint/config.yaml"]
