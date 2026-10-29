# Convenience targets. Go lives in /usr/local/go/bin on the dev machine.
GO ?= go
WEB_SRC ?= ../frontend/.output/public

.PHONY: build test vet fmt web run
build:
	$(GO) build -o bin/sdrscan-backend ./cmd/sdrscan-backend

test:
	$(GO) test ./... -count=1

vet:
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

# Copy the generated frontend (nuxt generate -> frontend/.output/public) into the embed directory.
web:
	find internal/webui/dist -mindepth 1 ! -name .gitkeep -delete
	cp -R $(WEB_SRC)/. internal/webui/dist/
	$(GO) build -o bin/sdrscan-backend ./cmd/sdrscan-backend

# Build and run with the settings in .env (copy .env.example first).
run: build
	@test -f .env || (echo "backend/.env not found: cp .env.example .env and edit it" && exit 1)
	set -a; . ./.env; set +a; ./bin/sdrscan-backend serve
