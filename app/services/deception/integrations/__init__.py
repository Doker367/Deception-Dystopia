"""Normalización de eventos de honeypots reales (Fase C).

Cada módulo traduce el formato de log nativo de un honeypot (Cowrie,
OpenCanary, Dionaea, Heralding, RedisHoneypot, Endlessh) al contrato ECS/
Dystopia común. ``adapters`` expone el registro de normalizadores; la
persistencia local vive en SQLite y ya no se publica a Elasticsearch.
"""
