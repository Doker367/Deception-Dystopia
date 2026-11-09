SHELL := /usr/bin/env bash

COMPOSE := docker compose --env-file .env -f docker-compose.yml

.PHONY: env check-docker build up down logs ps bootstrap-user attack health analytics-health token reset-ledger

env:
	@test -f .env || (umask 077; \
		printf 'NETPULSE_JWT_SECRET=%s\n' "$$(openssl rand -hex 32)" > .env; \
		echo "creado .env con un secreto nuevo")

check-docker:
	@docker info >/dev/null 2>&1 || { \
		echo "ERROR: Docker Desktop no está corriendo."; \
		echo "Abre Docker Desktop, espera a que diga 'Engine running' y reintenta."; \
		exit 1; }

build: env check-docker
	$(COMPOSE) build

up: env check-docker
	$(COMPOSE) up -d --wait

down: check-docker
	$(COMPOSE) down

logs: check-docker
	$(COMPOSE) logs --tail 80 -f collector control

ps: check-docker
	$(COMPOSE) ps

bootstrap-user: env check-docker
	@read -r -s -p "Contraseña del usuario lab (12+ caracteres): " P; echo; \
	test $${#P} -ge 12 || { echo "demasiado corta"; exit 1; }; \
	printf '%s' "$$P" | $(COMPOSE) run --rm -T --user 2000:2000 \
		-v "$(CURDIR)/bootstrap-user.py:/tmp/bootstrap-user.py:ro" \
		control python /tmp/bootstrap-user.py

attack: check-docker
	@curl --fail -sS -o /dev/null http://127.0.0.1:8082/api/health \
		|| { echo "ERROR: el control plane no responde en 127.0.0.1:8082."; \
		     echo "Ejecuta 'make up' y espera a que termine."; exit 1; }
	./attack-demo.sh

health: check-docker
	@curl --fail-with-body -sS http://127.0.0.1:8082/api/health

analytics-health: check-docker
	@test -s .token || { echo "No hay .token: ejecuta 'make token' primero."; exit 1; }
	@curl --fail-with-body -sS -H "Authorization: Bearer $$(cat .token)" \
		http://127.0.0.1:8082/api/analytics/health

token: env check-docker
	@if [ -s .token ] && [ "$${FORCE:-0}" != "1" ]; then \
		echo "reutilizando .token (usa FORCE=1 make token para renovarlo)"; \
	else \
		read -r -s -p "Contraseña del usuario lab: " P; echo; \
		T=$$(curl --fail-with-body -sS -X POST http://127.0.0.1:8082/api/auth/login \
			-H 'Content-Type: application/json' \
			--data "$$(jq -nc --arg p "$$P" '{username:"lab",password:$$p}')" \
			| jq -r '.access_token' 2>/dev/null); \
		unset P; \
		if [ -z "$$T" ] || [ "$$T" = "null" ]; then \
			echo "ERROR: login falló (¿usuario lab creado? ¿make bootstrap-user?)"; \
			exit 1; \
		fi; \
		umask 077; printf '%s' "$$T" > .token; echo "token guardado en .token"; \
	fi

reset-ledger: check-docker
	@$(COMPOSE) stop collector
	@$(COMPOSE) run --rm --user 2000:2000 -T -v "$(CURDIR)/reset-ledger.sql:/tmp/reset.sql:ro" \
		control python -c "import sqlite3; c=sqlite3.connect('/srv/deception/deception.db'); \
		c.executescript(open('/tmp/reset.sql').read()); c.commit(); print('ledger y heartbeat reseteados')"
	@$(COMPOSE) start collector
