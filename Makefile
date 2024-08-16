ifneq (,$(wildcard ./.env))
    include .env
    export
endif

PORT := $(PORT)

.PHONY: main

main: servelog.go main.go
	@go run servelog.go main.go
