APP_NAME=api
BIN_DIR=bin

.PHONY: build
build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o $(BIN_DIR)/$(APP_NAME) ./cmd/api

.PHONY: sam-build
sam-build:
	sam build

.PHONY: sam-deploy
sam-deploy:
	sam deploy --guided
