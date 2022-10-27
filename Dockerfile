# syntax=docker/dockerfile:1.2
FROM golang:1.19-alpine AS builder-env
ENV GO111MODULE="on"
ENV GOPROXY="https://goproxy.cn,direct"
RUN sed -i "s@https://dl-cdn.alpinelinux.org/@https://mirrors.huaweicloud.com/@g" /etc/apk/repositories
RUN apk update && apk add upx make

FROM builder-env AS builder
COPY . /build
WORKDIR /build
RUN --mount=type=cache,target=/go/pkg/mod go mod tidy
RUN make go-shijack
RUN upx go-shijack

FROM alpine:3
COPY --from=builder /build/go-shijack /
ENTRYPOINT ["/go-shijack"]
