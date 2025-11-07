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
