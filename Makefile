ifneq (,$(wildcard ./.env))
    include .env
    export
endif

COOKIE_FILE = ./cookies.txt
PORT := $(PORT)

.PHONY: main GET /login /logout

docker: docker_build
	docker run -p $(PORT):$(PORT) --env-file .env 9ziggy9.db

docker_build:
	docker build --no-cache -t 9ziggy9.db .

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
