GO ?= go
go-shijack:
	CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' ./cmd/go-shijack
container:
	docker buildx build -t ssst0n3/go-shijack .
test:
	go test ./...
# e2e needs CAP_NET_RAW (raw sockets + AF_PACKET). Run inside an unshared
# user+network namespace so it works as a normal user with no sudo and no
# pollution of the host network. -run TestE2E scopes to the real end-to-end
# cases only — unit tests belong to `make test`, spike probes are not gate
# tests.
e2e:
	unshare -Urn sh -c 'ip link set lo up && cd "$(CURDIR)" && $(GO) test -tags integration -run TestE2E -timeout 60s -v .'
