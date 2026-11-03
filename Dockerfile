# Governance Layer (p3dx_gov_layer) — Go REST service on port 8083.
#
# Build:  docker build -t p3dx-gov-layer .
# Run:    docker run --env-file .env -p 8083:8083 \
#           -v "$PWD/keys:/app/keys" -v "$PWD/data:/app/data" p3dx-gov-layer
#
# .env is NOT baked into the image — pass it at runtime with --env-file.
# Set APD_BASE_URL to the hosted dev APD. Inside the container "localhost" is
# the container itself, so point DB_HOST at the host's Postgres (e.g.
# --network host, or host.docker.internal).

# ---- build stage ----
FROM golang:1.26-bookworm AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gov-layer ./cmd/server
# grpcurl: Run TEE / job status call the Kata coordinator (CreateJob, GetJob) through it (GRPCURL_BIN).
# Built here with the same Go toolchain from a pinned release, with two of its dependencies raised past
# known CVEs (go-jose < 4.1.6, x/net < 0.60.0). Drop the extra versions once a grpcurl release includes them.
WORKDIR /grpcurl
RUN go mod init grpcurl-build \
    && go get github.com/fullstorydev/grpcurl/cmd/grpcurl@v1.9.4 github.com/go-jose/go-jose/v4@v4.1.6 golang.org/x/net@v0.60.0 \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=v1.9.4" -o /out/grpcurl github.com/fullstorydev/grpcurl/cmd/grpcurl

# ---- runtime stage ----
FROM debian:bookworm-slim

# python3: /final-model/inspect runs the embedded inspect_model.py (stdlib only).
# ca-certificates: HTTPS calls to Keycloak / catalogue / IUDX APD.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /app gov

WORKDIR /app
COPY --from=build /out/gov-layer /app/gov-layer
COPY --from=build /out/grpcurl /usr/local/bin/grpcurl

# keys/  — governance signing key (generated on first start; persist it, or
#          every new container signs contracts with a different key)
# data/  — STORE_PATH contracts.db for the legacy general-contract pathway
RUN mkdir -p /app/keys /app/data && chown -R gov:gov /app
USER gov

VOLUME ["/app/keys", "/app/data"]
# Approve TEE/SMPC jobs on the data-provider approval alone (no infra selected).
# Overridable at runtime (--env-file / -e REQUIRE_INFRA_APPROVAL=true).
ENV REQUIRE_INFRA_APPROVAL=false

EXPOSE 8083

ENTRYPOINT ["/app/gov-layer"]
