.PHONY: generate lint test build cedar-validate

VERSION ?= dev

generate:
	go generate ./...

lint:
	golangci-lint run --build-tags dev ./...

test:
	go test ./... -v -count=1

cedar-validate:
	cedar validate --schema internal/authz/policies/base.cedarschema --policies internal/authz/policies/base.cedar

build:
	go build -ldflags="-X main.version=$(VERSION)" -o bin/locker ./cmd/locker
	go build -ldflags="-X main.version=$(VERSION)" -o bin/gateway ./cmd/gateway
	go build -ldflags="-X main.version=$(VERSION)" -o bin/graph ./cmd/graph

.PHONY: build-fips
build-fips:
	GOFIPS140=latest go build -ldflags="-X main.version=$(VERSION)" -o bin/locker ./cmd/locker
	GOFIPS140=latest go build -ldflags="-X main.version=$(VERSION)" -o bin/gateway ./cmd/gateway
	GOFIPS140=latest go build -ldflags="-X main.version=$(VERSION)" -o bin/graph ./cmd/graph
