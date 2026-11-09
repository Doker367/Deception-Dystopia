SHELL := /usr/bin/env bash

COMPOSE := docker compose --env-file .env -f docker-compose.yml

.PHONY: env build up down logs ps bootstrap-user attack health analytics-health token reset-ledger

env:
	@test -f .env || (umask 077; \
		printf 'NETPULSE_JWT_SECRET=%s\n' "$$(openssl rand -hex 32)" > .env; \
		echo "creado .env con un secreto nuevo")

build: env
	$(COMPOSE) build

up: env
	$(COMPOSE) up -d --wait

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs --tail 80 -f collector control

ps:
	$(COMPOSE) ps

bootstrap-user: env
	@read -r -s -p "Contraseña del usuario lab (12+ caracteres): " P; echo; \
	test $${#P} -ge 12 || { echo "demasiado corta"; exit 1; }; \
	printf '%s' "$$P" | $(COMPOSE) run --rm -T --user 0 \
		-v "$(CURDIR)/bootstrap-user.py:/tmp/bootstrap-user.py:ro" \
		control python /tmp/bootstrap-user.py

attack:
	./attack-demo.sh

health:
	@curl --fail-with-body -sS http://127.0.0.1:8082/api/health

analytics-health: token
	@curl --fail-with-body -sS -H "Authorization: Bearer $$(cat .token)" \
		http://127.0.0.1:8082/api/analytics/health

token: env
	@read -r -s -p "Contraseña del usuario lab: " P; echo; \
	T=$$(curl --fail-with-body -sS -X POST http://127.0.0.1:8082/api/auth/login \
		-H 'Content-Type: application/json' \
		--data "$$(jq -nc --arg p "$$P" '{username:"lab",password:$$p}')" \
		| jq -r '.access_token'); \
	unset P; test -n "$$T" -a "$$T" != null; \
	umask 077; printf '%s' "$$T" > .token; echo "token guardado en .token"

reset-ledger:
	@$(COMPOSE) stop collector
	@$(COMPOSE) run --rm --user 0 -T -v "$(CURDIR)/reset-ledger.sql:/tmp/reset.sql:ro" \
		control python -c "import sqlite3; c=sqlite3.connect('/srv/deception/deception.db'); \
		c.executescript(open('/tmp/reset.sql').read()); c.commit(); print('ledger y heartbeat reseteados')"
	@$(COMPOSE) start collector
