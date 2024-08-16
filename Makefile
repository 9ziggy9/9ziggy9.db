ifneq (,$(wildcard ./.env))
    include .env
    export
endif

COOKIE_FILE = ./cookies.txt
PORT := $(PORT)

.PHONY: main GET /login /logout

main: main.go
	@go run main.go

GET:
	curl -b $(COOKIE_FILE) http://localhost:$(PORT)$(RROUTE)

/login:
	curl -c $(COOKIE_FILE) -X POST http://localhost:$(PORT)/login \
     -d "name=$(RNAME)"                                         \
     -d "pwd=$(RPWD)"

/logout:
	curl -c $(COOKIE_FILE) http://localhost:$(PORT)/logout

clean:
	rm -rf $(COOKIE_FILE)
