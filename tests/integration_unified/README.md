# Unified integration tests — Dystopia + T-Pot + Elasticsearch/Kibana

Test-owned area for Agent 6 (QA/integration). These tests never start Dystopia,
T-Pot, Elasticsearch, Kibana, Docker, libvirt or a VM, and never change firewall
or network state. They are executable with the standard library, so they also
work when the application dependencies are not installed.

## Layers

| Layer | Command | Requires services? |
|---|---|---|
| Offline contract + artifact checks | `scripts/smoke_unified.sh` (default) | No |
| Opt-in lab preflight | `scripts/smoke_unified.sh --lab` | Disposable lab only |
| Opt-in lab full flow | `scripts/smoke_unified.sh --lab --full` | Disposable lab only |

Direct pytest/unittest runs are equivalent:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/integration_unified -p 'test_*.py' -v
```

## Contract encoded by the fixtures

Inputs:

- Dystopia `runtime.contracts` v1 events (`event_id`, `device_id`,
  `observed_at`, `src_ip`, `type`, `proto`, optional ports/detail).
- Raw Cowrie JSON lines (`eventid`, `timestamp`, `src_ip/src_port`,
  `dst_ip/dst_port`, `session`, `message`, protocol-specific fields).
- Dystopia topology as the source of truth for `segment_id`, `instance_id`,
  `persona` and destination address.

Output document (ECS shape):

- `@timestamp`, stable `event.id`, `event.action/dataset/outcome/category`.
- `source.ip[/port]`, `destination.ip/port`, `network.transport/protocol`,
  `observer.name/product`, `session.id`.
- `dystopia.schema_version`, `dystopia.device_id`, `dystopia.segment_id`,
  `dystopia.instance_id`, `dystopia.persona`.

Identity rule: `event.id` is globally unique and stable; it is the Elasticsearch
document id (`PUT _doc/{event.id}`). Producers fold observer/device/session and
a raw fingerprint into the derivation when the honeypot id is not globally
unique. Replaying a batch is idempotent. The same id with different content is a
conflict and must never overwrite the first document.

Secret rule: captured passwords and command payloads are dropped or confined to
the restricted container declared by the production mapping; they never appear
in publisher logs or Kibana filters. Test fixtures include a synthetic canary
(`SYNTHETIC-CANARY-PASSWORD-...`) whose only purpose is to prove the scan works.

## Fixtures

| File | Purpose |
|---|---|
| `fixtures/topology.json` | Synthetic segments/devices/personas |
| `fixtures/events_native.jsonl` | Strict Dystopia v1 events |
| `fixtures/events_cowrie.jsonl` | Cowrie session with synthetic password canary |
| `fixtures/duplicates_scenario.json` | Ack loss + publisher restart replay |
| `fixtures/mapping_expected.json` | Expected `deception-events*` mapping/data-view contract |
| `fixtures/kibana_filters.json` | Data view + filters with expected result sets |
| `fixtures/logs/publisher_clean.log` | Clean publisher log for the secret scanner |
| `fixtures/lab_scenario.example.json` | Inert template for the opt-in lab flow |

Synthetic addresses are RFC 5737 ranges; no test connects to them.

## Opt-in lab gates

The harness refuses to execute unless **all** of these are explicit:

- `DYSTOPIA_LAB_E2E=preflight|full`
- `DYSTOPIA_LAB_CONFIRM=DISPOSABLE-LAB-ONLY`
- `DYSTOPIA_LAB_MARKER`: operator-created file with
  `purpose=dystopia-disposable-lab` and `authorization_id=<id>`.
- `DYSTOPIA_LAB_TARGETS`: explicit comma-separated allowlist. Only RFC1918,
  loopback and ULA literals (or `*.lab`/`*.lab.local`/`*.test`) are accepted;
  public, documentation, carrier-grade, multicast and link-local/metadata
  addresses are refused.
- `DYSTOPIA_LAB_SCENARIO`: operator scenario. No inline credentials; token
  files must be owner-only (0600/0400). Plain HTTP is accepted only on loopback.
- Every scenario host must be in `DYSTOPIA_LAB_TARGETS`.

The automated flow performs only health/read requests plus one publisher restart
POST. The benign SSH login is performed by the operator; the test then waits for
`DYSTOPIA_LAB_SSH_PERFORMED=<scenario.ssh.performed_token>` and verifies
persistence, one document per `event.id`, deployed mapping, Kibana data view,
configured filters and no duplicates after the publisher restart. It never opens
SSH, sends credentials or attacks anything.

## Skips are intentional

- No lab environment variable → every lab test skips with the exact variables
  required.
- No production Elasticsearch templates / Kibana NDJSON yet → artifact test
  skips with the paths it looked for.
- `DYSTOPIA_LOG_ARTIFACT` not set → external log scan skips; the bundled clean
  log and synthetic dirty-log tests always run.

Skips mean "the artifact does not exist yet"; they are never a green result for
the real integration. A failing artifact test is a finding for the owning agent,
not something to silence by reverting the contract.
