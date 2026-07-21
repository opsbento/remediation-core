FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN go build -o /out/remediate ./cmd/remediate

FROM alpine:3.22
ARG SYFT_VERSION=1.27.1
ARG GRYPE_VERSION=0.96.0
RUN apk add --no-cache ca-certificates curl git nodejs npm tar \
  && arch="$(apk --print-arch)" \
  && case "$arch" in \
    aarch64) platform="linux_arm64" ;; \
    x86_64) platform="linux_amd64" ;; \
    *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
  esac \
  && curl -fsSL "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_${platform}.tar.gz" \
    | tar -xz -C /usr/local/bin syft \
  && curl -fsSL "https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_${platform}.tar.gz" \
    | tar -xz -C /usr/local/bin grype
COPY --from=build /out/remediate /usr/local/bin/remediate
ENTRYPOINT ["remediate"]
