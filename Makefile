.PHONY: help
help:
	@echo "No helps today, check the Makefile 😛"

.PHONY: dev
dev:
	air -c ./.dev/.air.toml

.PHONY: devstack
devstack:
	docker compose --file ./.dev/compose.yaml --env-file ./.dev/.env up --detach

.PHONY: devstack.rm
devstack.rm:
	docker compose --file ./.dev/compose.yaml --env-file ./.dev/.env down

.PHONY: staging
staging:
	docker compose --file ./deploy/compose.yaml --env-file ./deploy/.env up --detach

.PHONY: staging.rm
staging.rm:
	docker compose --file ./deploy/compose.yaml --env-file ./deploy/.env down

.PHONY: pair
pair:
	@KEY=$$(openssl rand -base64 32); \
	echo "Secret Key: $$KEY"; \
	echo "DIGEST: $$( go run ./cmd/keygen/main.go $$KEY )";

