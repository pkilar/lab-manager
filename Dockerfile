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
# busybox wget (bundled in alpine) backs the compose/stack healthcheck.
FROM alpine:3.21

RUN apk add --no-cache ipmitool ca-certificates

WORKDIR /app
COPY --from=build /out/lab-manager /app/lab-manager

# Created here for non-volume runs; compose/stack bind- or named-mount over it.
RUN mkdir -p /app/instance

EXPOSE 5000

ENTRYPOINT ["/app/lab-manager"]
