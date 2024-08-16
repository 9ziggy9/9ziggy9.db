ifneq (,$(wildcard ./.env))
    include .env
    export
endif

PORT := $(PORT)

.PHONY: main

main: main.go
	@go run main.go
