.PHONY: generate lint test build

generate:
	go generate ./...

lint:
	golangci-lint run --build-tags dev ./...

test:
	go test ./... -v -count=1

build:
	go build -o bin/locker ./cmd/locker
	go build -o bin/gateway ./cmd/gateway
	# go build -o bin/graph ./cmd/graph      # Plan 3

.PHONY: build-fips
build-fips:
	GOFIPS140=latest go build -o bin/locker ./cmd/locker
	GOFIPS140=latest go build -o bin/gateway ./cmd/gateway
	# GOFIPS140=latest go build -o bin/graph ./cmd/graph      # Plan 3
