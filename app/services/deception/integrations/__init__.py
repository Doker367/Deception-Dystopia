"""Normalización de eventos de honeypots reales (Fase C).

Cada módulo traduce el formato de log nativo de un honeypot (Cowrie,
OpenCanary, Dionaea, Heralding, RedisHoneypot, Endlessh) al contrato ECS/
Dystopia común. ``adapters`` expone el registro y ``elastic_svc`` el
publicador idempotente, deshabilitado por defecto.
"""
