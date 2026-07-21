.PHONY: build test fmt vet

build:
	go build ./cmd/remediate

test:
	go test ./...

fmt:
	gofmt -w cmd internal

vet:
	go vet ./...
