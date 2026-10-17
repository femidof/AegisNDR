# CI only: build the pinned upstream sources when vendor images are unavailable.
FROM golang:1.24.3-alpine3.21 AS build
ARG COMPONENT
ARG RELEASE
ENV CGO_ENABLED=0 GOBIN=/out GOMAXPROCS=2
RUN go install -p 2 github.com/minio/${COMPONENT}@${RELEASE}

FROM alpine:3.22.1
RUN apk add --no-cache ca-certificates curl \
 && mkdir -p /data /home/minio \
 && chown 65532:65532 /data /home/minio
COPY --from=build /out/ /usr/local/bin/
ENV HOME=/home/minio
VOLUME ["/data"]
USER 65532:65532
# Compose selects the server command; minio-init overrides this for its script.
ENTRYPOINT ["minio"]
