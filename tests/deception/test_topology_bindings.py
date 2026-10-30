"""Pruebas unitarias del binding de servicios señuelo a honeypots externos.

Agente 1 (topología y control). Alcance exclusivo: app/models/deception.py
y app/services/deception/topology_svc.py. Dependencias mínimas
(pydantic/PyYAML/pytest) en entorno aislado; sin FastAPI, sin arranque de
servicios ni red: el flujo queda binding declarativo.
"""

import sys
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from app.models.deception import (  # noqa: E402
    EXTERNAL_ENGINES,
    DeceptionEngine,
    DeceptionNetwork,
    DeceptionService,
)
from app.services.deception import topology_svc  # noqa: E402


def _write_network(tmp_path, network) -> Path:
    f = tmp_path / "network.yaml"
    f.write_text(yaml.safe_dump(network), encoding="utf-8")
    return f


@pytest.fixture()
def net_file(tmp_path, monkeypatch):
    """YAML temporal con un binding externo válido y uno legacy sin instance."""
    network = {
        "segments": [
            {"id": "vlan-servidores", "vlan_id": 20, "cidr": "10.20.0.0/24",
             "gateway": "10.20.0.1"},
            {"id": "vlan-oficina", "vlan_id": 10, "cidr": "10.10.0.0/24"},
        ],
        "devices": [
            {
                "id": "srv-files-01", "role": "server", "segment": "vlan-servidores",
                "ip": "10.20.0.10",
                "persona": {"vendor": "linux", "os": "ubuntu", "hostname": "files01"},
                "services": [
                    {"port": 2222, "proto": "ssh", "engine": "cowrie",
                     "instance": "cowrie-dmz-01", "banner": "OpenSSH_8.2p1"},
                    {"port": 2223, "proto": "telnet", "engine": "cowrie",
                     "instance": "cowrie-dmz-01"},
                    {"port": 80, "proto": "http", "engine": "native"},
                ],
            },
            {
                "id": "pc-01", "role": "pc", "segment": "vlan-oficina",
                "ip": "10.10.0.21",
                "services": [
                    {"port": 445, "proto": "smb", "engine": "dionaea"},
                ],
            },
        ],
    }
    f = _write_network(tmp_path, network)
    monkeypatch.setattr(topology_svc, "NETWORK_FILE", f)
    topology_svc.invalidate_cache()
    return f


def _dev(**over):
    base = {"id": "srv-x", "role": "server", "segment": "vlan-a",
            "ip": "10.20.0.10",
            "services": [{"port": 2222, "proto": "ssh", "engine": "cowrie",
                          "instance": "cowrie-a"}]}
    base.update(over)
    return base


# ── Modelos: motores externos MVP y formato de instancia ─────


def test_motores_externos_mvp():
    """Motores catalogados en T-Pot presentes y separados de los internos."""
    mvp = {"cowrie", "opencanary", "dionaea", "heralding",
           "redishoneypot", "endlessh"}
    assert mvp <= {e.value for e in DeceptionEngine}
    externos = {e.value for e in EXTERNAL_ENGINES}
    assert mvp <= externos
    assert "native" not in externos and "go" not in externos


def test_formato_identificador_instancia():
    for ok in ("cowrie-dmz-01", "a", "heralding_dev_1", "x0-x0-x0"):
        svc = DeceptionService(port=22, proto="ssh", engine="cowrie", instance=ok)
        assert svc.instance == ok
    for malo in ("Cowrie-01", "", "-cowrie", "cowrie-", "cowrie/dmz",
                 "cowrie dmz", "a" * 65):
        with pytest.raises(ValidationError):
            DeceptionService(port=22, proto="ssh", engine="cowrie", instance=malo)


def test_instance_opcional_en_modelo():
    """Compatibilidad: servicios sin instance (modo legacy) siguen válidos."""
    svc = DeceptionService(port=22, proto="ssh", engine="cowrie")
    assert svc.instance is None
    svc = DeceptionService(port=80, proto="http")
    assert svc.engine == DeceptionEngine.NATIVE


# ── Vista de binding y resolución del contrato de eventos ────


def test_vista_external_bindings(net_file):
    bindings = topology_svc.external_bindings()
    # Solo servicios externos CON instance: nativos y legacy quedan fuera.
    assert len(bindings) == 2
    ssh = next(b for b in bindings if b["port"] == 2222)
    assert ssh["engine"] == "cowrie"
    assert ssh["instance"] == "cowrie-dmz-01"
    assert ssh["device_id"] == "srv-files-01"
    assert ssh["segment_id"] == "vlan-servidores"
    assert ssh["device_ip"] == "10.20.0.10"
    assert ssh["device_enabled"] is True
    assert ssh["persona"]["hostname"] == "files01"
    assert ssh["banner"] == "OpenSSH_8.2p1"
    tel = next(b for b in bindings if b["port"] == 2223)
    assert tel["instance"] == "cowrie-dmz-01"
    assert all("password" not in str(b) for b in bindings)  # sin credenciales


def test_binding_status_y_summary(net_file):
    status = topology_svc.binding_status()
    assert status["bound"] == 2
    assert status["by_engine"] == {"cowrie": 2}
    assert status["instances"] == ["cowrie-dmz-01"]
    assert status["unbound"] == [
        {"device_id": "pc-01", "segment_id": "vlan-oficina",
         "engine": "dionaea", "proto": "smb", "port": 445}
    ]
    summary = topology_svc.summary()
    assert summary["external_bound"] == 2
    assert summary["external_unbound"] == 1


def test_resolve_instance_contrato_eventos(net_file):
    """instance_id resuelve device_id/segment_id/persona (contrato ingestión)."""
    res = topology_svc.resolve_instance("cowrie-dmz-01")
    assert res is not None
    assert res["instance_id"] == "cowrie-dmz-01"
    assert res["engine"] == "cowrie"
    assert res["device_id"] == "srv-files-01"
    assert res["segment_id"] == "vlan-servidores"
    assert res["persona"]["hostname"] == "files01"
    assert {b["port"] for b in res["bindings"]} == {2222, 2223}
    # device_id y segment_id también resolubles por funciones existentes
    dev = topology_svc.get_device(res["device_id"])
    seg = topology_svc.get_segment(res["segment_id"])
    assert dev is not None and seg is not None
    assert dev["persona"] == res["persona"]
    # Filtros y desconocidos
    assert topology_svc.resolve_instance("cowrie-dmz-01", engine="dionaea") is None
    assert topology_svc.resolve_instance("no-existe") is None


# ── Validate: referencias, puertos, IP/segmento, instancias ──


def test_validate_red_valida(net_file):
    rep = topology_svc.validate_topology()
    assert rep["errors"] == []
    assert any("dionaea" in w and "'instance'" in w for w in rep["warnings"])


def test_validate_errores_cruzados():
    network = DeceptionNetwork.model_validate({
        "segments": [{"id": "vlan-a", "cidr": "10.20.0.0/24"},
                     {"id": "vlan-b", "cidr": "10.30.0.0/24"}],
        "devices": [
            _dev(),
            # misma instancia en otro dispositivo → conflicto global
            _dev(id="srv-y", ip="10.30.0.5", segment="vlan-b"),
            # puerto/proto duplicado en el propio dispositivo
            _dev(id="srv-z", ip="10.20.0.12", segment="vlan-a",
                 services=[{"port": 22, "proto": "ssh"},
                           {"port": 22, "proto": "ssh"}]),
        ],
    })
    rep = topology_svc.validate_topology(network)
    joined = "; ".join(rep["errors"])
    assert "ya está vinculada al dispositivo 'srv-x'" in joined
    assert "duplica el servicio ssh/22" in joined
    assert "srv-y" in joined  # el conflicto menciona ambos dispositivos


def test_validate_ip_fuera_de_cidr():
    network = DeceptionNetwork.model_validate({
        "segments": [{"id": "vlan-a", "cidr": "10.20.0.0/24"}],
        "devices": [_dev(ip="10.99.0.1")],
    })
    rep = topology_svc.validate_topology(network)
    assert any("no pertenece al CIDR" in e for e in rep["errors"])


def test_validate_cidr_invalido_y_segmento_inexistente():
    """CIDR malformado pasa el modelo (str) y lo detecta la capa de servicio."""
    network = DeceptionNetwork.model_validate({
        "segments": [{"id": "vlan-m", "cidr": "10.300.0.0/24"}],
        "devices": [{"id": "srv-m", "role": "server", "segment": "vlan-m",
                     "ip": "10.20.0.1"}],
    })
    rep = topology_svc.validate_topology(network)
    assert any("no pertenece al CIDR" in e for e in rep["errors"])
    # add_segment sí rechaza CIDRs inválidos al escribir (ver test propio).
    network_vacio = DeceptionNetwork.model_validate({"segments": [], "devices": []})
    assert topology_svc.validate_topology(network_vacio)["errors"] == []
    # dispositivo que referencia un segmento inexistente → error del reporte
    network_huerfano = DeceptionNetwork.model_validate(
        {"segments": [], "devices": [_dev(id="orphan")]})
    rep = topology_svc.validate_topology(network_huerfano)
    assert any("segmento inexistente" in e for e in rep["errors"])


# ── Escrituras: validación estricta al crear/actualizar ──────


def test_add_device_con_binding_valido(net_file):
    out = topology_svc.add_device({
        "id": "srv-db-01", "role": "server", "segment": "vlan-servidores",
        "ip": "10.20.0.11",
        "services": [{"port": 3322, "proto": "ssh", "engine": "opencanary",
                      "instance": "opencanary-dmz-01"}],
    })
    assert out["services"][0]["instance"] == "opencanary-dmz-01"
    res = topology_svc.resolve_instance("opencanary-dmz-01")
    assert res is not None
    assert res["device_id"] == "srv-db-01"


def test_add_device_instancia_repetida_en_otro_device(net_file):
    with pytest.raises(ValueError, match="ya está vinculada"):
        topology_svc.add_device({
            "id": "srv-otro", "role": "server", "segment": "vlan-servidores",
            "ip": "10.20.0.12",
            "services": [{"port": 2222, "proto": "ssh", "engine": "cowrie",
                          "instance": "cowrie-dmz-01"}],
        })


def test_add_device_instancia_compartida_mismo_device_ok(net_file):
    """Un honeypot (instance) puede atender varios puertos del device."""
    topology_svc.add_device({
        "id": "srv-multi", "role": "server", "segment": "vlan-servidores",
        "ip": "10.20.0.13",
        "services": [
            {"port": 3200, "proto": "ssh", "engine": "heralding",
             "instance": "heralding-dmz-01"},
            {"port": 3201, "proto": "telnet", "engine": "heralding",
             "instance": "heralding-dmz-01"},
        ],
    })
    res = topology_svc.resolve_instance("heralding-dmz-01")
    assert {b["port"] for b in res["bindings"]} == {3200, 3201}


def test_add_device_formato_instancia_invalido(net_file):
    with pytest.raises(ValueError, match="instancia"):
        topology_svc.add_device({
            "id": "srv-bad", "role": "server", "segment": "vlan-servidores",
            "ip": "10.20.0.14",
            "services": [{"port": 2200, "proto": "ssh", "engine": "cowrie",
                          "instance": "Cowrie/DMZ"}],
        })


def test_add_device_externo_sin_instance_rechazado(net_file):
    """El binding externo exige instance explícita al escribir."""
    with pytest.raises(ValueError, match="requiere una 'instance'"):
        topology_svc.add_device({
            "id": "srv-legacy", "role": "server", "segment": "vlan-servidores",
            "ip": "10.20.0.15",
            "services": [{"port": 2100, "proto": "ssh", "engine": "endlessh"}],
        })


def test_add_device_puerto_duplicado_y_ip_fuera_de_cidr(net_file):
    with pytest.raises(ValueError, match="duplica"):
        topology_svc.add_device({
            "id": "srv-dup", "role": "server", "segment": "vlan-servidores",
            "ip": "10.20.0.16",
            "services": [{"port": 3311, "proto": "ssh", "instance": "h1",
                          "engine": "cowrie"},
                         {"port": 3311, "proto": "ssh", "instance": "h2",
                          "engine": "cowrie"}],
        })
    with pytest.raises(ValueError, match="CIDR"):
        topology_svc.add_device({
            "id": "srv-ip", "role": "server", "segment": "vlan-servidores",
            "ip": "172.16.0.9",
            "services": [{"port": 3312, "proto": "http"}],
        })


def test_update_device_validaciones(net_file):
    ok = topology_svc.update_device("srv-files-01", {"ip": "10.20.0.9"})
    assert ok["ip"] == "10.20.0.9"
    # ip que sale del CIDR del segmento → rechazo
    with pytest.raises(ValueError, match="CIDR"):
        topology_svc.update_device("srv-files-01", {"ip": "10.99.0.1"})
    # el legado sin instance de OTRO device no bloquea escribir en este
    assert topology_svc.update_device("pc-01", {"ip": "10.10.0.22"})["ip"] == "10.10.0.22"


def test_add_segment_cidr_invalido(net_file):
    with pytest.raises(ValueError, match="CIDR"):
        topology_svc.add_segment({"id": "vlan-mal", "cidr": "no-es-cidr"})


# ── Ejemplos config/deception: siguen válidos ────────────────


@pytest.mark.skipif(
    not (REPO / "config/deception/network.dev.yaml").exists(),
    reason="ejemplo dev ausente",
)
def test_ejemplo_dev_valido_y_con_binding():
    raw = yaml.safe_load(
        (REPO / "config/deception/network.dev.yaml").read_text(encoding="utf-8")
    )
    network = DeceptionNetwork.model_validate(raw)
    rep = topology_svc.validate_topology(network)
    assert rep["errors"] == [], rep["errors"]
    bindings = topology_svc.external_bindings(network)
    engines = {b["engine"] for b in bindings}
    assert {"cowrie", "endlessh", "heralding", "redishoneypot"} <= engines
    res = topology_svc.resolve_instance("cowrie-dev-01", network=network)
    assert res is not None
    assert res["device_id"] == "srv-dev-01"


@pytest.mark.skipif(
    not (REPO / "config/deception/network.yaml").exists(),
    reason="configuración real ausente",
)
def test_configuracion_real_sin_errores():
    """La topología real carga sin errores (warnings legacy admitidos)."""
    raw = yaml.safe_load(
        (REPO / "config/deception/network.yaml").read_text(encoding="utf-8")
    )
    network = DeceptionNetwork.model_validate(raw)
    rep = topology_svc.validate_topology(network)
    assert rep["errors"] == [], rep["errors"]
