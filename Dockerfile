# ---- build stage -----------------------------------------------------------
# Pure-Go build (CGO disabled): modernc.org/sqlite needs no C toolchain, so the
# result is a fully static binary with the templates and tzdata embedded.
# Pinned to the BUILD platform so the compiler always runs natively and
# cross-compiles to each TARGET arch — fast multi-arch builds with no emulation
# of the toolchain.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Cache module downloads separately from the source for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o /out/lab-manager ./cmd/lab-manager

# ---- runtime stage ---------------------------------------------------------
# ipmitool is required for IPMI power control; ca-certificates for outbound TLS;
# su-exec drops root in the entrypoint; busybox wget (bundled in alpine) backs
# the compose/stack healthcheck.
FROM alpine:3.24

RUN apk add --no-cache ipmitool ca-certificates su-exec

WORKDIR /app
COPY --from=build /out/lab-manager /app/lab-manager
COPY --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# Created here for non-volume runs; compose/stack bind- or named-mount over it.
RUN mkdir -p /app/instance

EXPOSE 5000

# The entrypoint starts as root only to re-own /app/instance (migrating volumes
# written by older root-run images), then execs the app as an unprivileged
# user: 10001:10001 by default, PUID/PGID to override. Nothing the app does
# needs root: ipmitool, Redfish and WoL broadcasts are ordinary UDP/TCP from a
# high port, and it listens on 5000.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/app/lab-manager"]
