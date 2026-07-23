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
EXPOSE 8080
ENV PORT=8080
ENTRYPOINT ["/app/custodian", "serve"]
