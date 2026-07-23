.PHONY: test build run tidy

test:
	go test ./...

build:
	go build -o bin/custodian ./cmd/custodian

tidy:
	go mod tidy

run: build
	./bin/custodian serve
