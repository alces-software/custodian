# Build
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/custodian ./cmd/custodian

# Run
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /app
COPY --from=build /out/custodian /app/custodian
USER nonroot:nonroot
# Do not EXPOSE a port or bake PORT here — Dokku injects PORT and maps
# host http:80 / https:443 → container $PORT. Hardcoding EXPOSE 8080 makes
# Dokku treat 8080 as the public proxy port instead of the usual 80/443 setup.
ENTRYPOINT ["/app/custodian", "serve"]
