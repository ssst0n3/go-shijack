GO ?= go
go-shijack:
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' ./cmd/go-shijack
container:
	docker buildx build -t ssst0n3/go-shijack .
