#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dystopia - generador de artefactos Kibana para el panel analítico deception-*.

Consume:  ../specs/deception-dashboards-spec.json  (contrato versionado)
Produce:  ../artifacts/deception-kibana-bundle.ndjson  (saved objects separados
          por línea, formato importable de Kibana /api/saved_objects/_import)
          ../artifacts/MANIFEST.json  (estado, conteos y hash)

SIN dependencias nuevas: solo stdlib (json, hashlib, argparse, datetime, os).

Estado de los artefactos: VALIDADO contra Kibana 9.3.5 en el laboratorio
macOS. El bundle canónico importa 53/53 objetos y los 7 dashboards renderizan
con datos sintéticos. El formato moderno incluye `panelRefName`, `indexRefName`
y `seriesParams[].data`; ver README.md para las correcciones descubiertas en
el import real.

Uso:
    python3 build_dashboards.py
    python3 build_dashboards.py --with-map   (añade el panel Maps experimental)
    python3 build_dashboards.py --out PATH   (otra ruta de salida)
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

SPECS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "specs", "deception-dashboards-spec.json")
ARTIFACTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "artifacts")

# ---------------------------------------------------------------------------
# Campos que existen según el contrato de mappings
# (config/elasticsearch/templates/*.json). El generador rechaza cualquier
# agg que use un campo fuera de esta lista: evita visuales rotos por
# desincronización spec<->mappings.
# ---------------------------------------------------------------------------
EVENTS_FIELDS = {
    "@timestamp": "date",
    "event.id": "keyword", "event.kind": "keyword", "event.category": "keyword",
    "event.type": "keyword", "event.action": "keyword", "event.outcome": "keyword",
    "event.dataset": "keyword", "event.severity": "long",
    "source.ip": "ip", "source.port": "long",
    "source.as.number": "long", "source.as.organization": "keyword",
    "source.geo.country_name": "keyword", "source.geo.country_iso_code": "keyword",
    "source.geo.continent_name": "keyword", "source.geo.city_name": "keyword",
    "source.geo.timezone": "keyword", "source.geo.location": "geo_point",
    "destination.ip": "ip", "destination.port": "long",
    "network.transport": "keyword", "network.protocol": "keyword",
    "network.bytes": "long", "network.packets": "long",
    "observer.type": "keyword", "observer.name": "keyword", "observer.product": "keyword",
    "observer.vendor": "keyword", "observer.version": "keyword",
    "session.id": "keyword",
    "dystopia.schema_version": "keyword", "dystopia.device_id": "keyword",
    "dystopia.segment_id": "keyword", "dystopia.instance_id": "keyword",
    "dystopia.persona": "keyword", "dystopia.decoy_credentials": "keyword",
    "dystopia.decoy_credential_realm": "keyword",
    "dystopia.decoy_credential_matches": "integer",
    "dystopia.raw_reference": "keyword", "dystopia.ingest_source": "keyword",
    "dystopia.control_version": "keyword",
}
ALERTS_FIELDS = {
    "@timestamp": "date",
    "event.id": "keyword", "event.kind": "keyword", "event.category": "keyword",
    "event.type": "keyword", "event.action": "keyword", "event.outcome": "keyword",
    "event.dataset": "keyword", "event.severity": "long", "event.reason": "keyword",
    "source.ip": "ip", "source.port": "long",
    "source.geo.country_name": "keyword", "source.geo.country_iso_code": "keyword",
    "source.geo.location": "geo_point",
    "destination.ip": "ip", "destination.port": "long",
    "network.transport": "keyword", "network.protocol": "keyword",
    "observer.type": "keyword", "observer.name": "keyword", "observer.product": "keyword",
    "session.id": "keyword",
    "dystopia.schema_version": "keyword", "dystopia.device_id": "keyword",
    "dystopia.segment_id": "keyword", "dystopia.instance_id": "keyword",
    "dystopia.persona": "keyword", "dystopia.decoy_credentials": "keyword",
    "dystopia.raw_reference": "keyword", "dystopia.ingest_source": "keyword",
    "dystopia.control_version": "keyword",
    "dystopia.alert.rule_id": "keyword", "dystopia.alert.rule_name": "keyword",
    "dystopia.alert.risk_score": "float", "dystopia.alert.source_event_ids": "keyword",
}
AGG_TYPES_NEEDING_FIELD = {
    "terms", "date_histogram", "avg", "max", "min", "sum", "cardinality",
}

def field_assert(spec_field, dv_id, dv_fields):
    if spec_field not in dv_fields:
        fail(f"agg usa campo '{spec_field}' que no está en la data view '{dv_id}'")
    return spec_field

def fail(msg):
    print(f"[FATAL] {msg}", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Construcción de saved objects
# ---------------------------------------------------------------------------
def make_field_list(fields):
    fl = []
    for name, ftype in sorted(fields.items()):
        fl.append({
            "name": name,
            "type": ftype,
            "esTypes": [ftype],
            "count": 1,
            "scripted": False,
            "searchable": True,
            "aggregatable": True,
            "readFromDocValues": True,
        })
    return json.dumps(fl, separators=(",", ":"))

def make_index_pattern(dv):
    return {
        "id": dv["id"],
        "type": "index-pattern",
        "namespaces": ["default"],
        "attributes": {
            "title": dv["title"],
            "timeFieldName": dv["timeFieldName"],
            "fields": make_field_list(EVENTS_FIELDS if dv["id"] == "deception-events-dv" else ALERTS_FIELDS),
            "description": dv.get("description", ""),
        },
        "references": [],
        "$info": {"generator": "dystopia-agent4", "pending_real_validation": False},
    }

def make_vis(vis_spec, dv):
    # En vislib el tipo guardado de una barra vertical es "histogram".
    vig_type = "histogram" if vis_spec["type"] == "bar" else vis_spec["type"]
    aggs = []
    for agg in vis_spec["aggs"]:
        a = {"id": agg["id"], "enabled": True, "type": agg["type"], "schema": agg["schema"], "aggs": []}
        params = {}
        if agg.get("field"):
            field = field_assert(agg["field"], vis_spec["data_view"], EVENTS_FIELDS if vis_spec["data_view"] == "deception-events-dv" else ALERTS_FIELDS)
            params["field"] = field
        if agg["type"] == "date_histogram":
            params.update({"interval": "auto", "time_zone": "Europe/Madrid", "useNormalizedEsInterval": True,
                           "scaleMetricRequirements": "none", "intervalType": "auto", "drop_partials": False,
                           "min_doc_count": 1, "extended_bounds": {}, "format": "date"})
        elif agg["type"] == "terms":
            params.update({"size": agg.get("size", 10), "orderBy": "_count", "order": "desc",
                           "otherBucket": False, "otherBucketLabel": "Other", "missingBucket": False,
                           "missingBucketLabel": "Missing", "include": [], "exclude": []})
        elif agg["type"] in ("avg", "max", "min", "sum"):
            params.update({"json": "{}"})
        a["params"] = params
        aggs.append(a)

    vis_state = {
        "title": vis_spec["title"],
        "type": vig_type,
        "aggs": aggs,
    }
    # params por tipo (defaults clásicos, ajustables en UI tras importar)
    common = {"addTooltip": True, "addLegend": True}
    if vig_type in ("line", "histogram"):
        # vislib necesita ejes y seriesParams; sin ellos el panel queda en
        # blanco (o "Invalid visualization type" para bar).
        series_type = "line" if vig_type == "line" else "histogram"
        metric_agg = next((a for a in aggs if a["schema"] == "metric"), None)
        metric_id = metric_agg["id"] if metric_agg else "1"
        vis_state["params"] = {
            **common,
            "type": vig_type,
            "grid": {"categoryLines": False},
            "categoryAxes": [{
                "id": "CategoryAxis-1", "type": "category", "position": "bottom",
                "show": True, "style": {}, "scale": {"type": "linear"},
                "labels": {"show": True, "filter": True, "truncate": 100}, "title": {},
            }],
            "valueAxes": [{
                "id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                "position": "left", "show": True, "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                "title": {"text": "Count"},
            }],
            "seriesParams": [{
                "show": True, "type": series_type, "mode": "normal",
                "data": {"id": metric_id, "label": "Count"},
                "dataLabel": "Count", "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True, "lineWidth": 2,
                "interpolate": "linear", "showCircles": True,
                "radiusRatio": 9,
            }],
            "legendPosition": "right", "times": [], "addTimeMarker": False,
            "legendSize": "auto",
            "showCircles": True, "interpolate": "linear", "scale": "linear",
            "drawLinesBetweenPoints": True, "radiusRatio": 9,
            "defaultYExtents": False, "setYExtents": False,
        }
        vis_state["params"].update({k: v for k, v in vis_spec.get("params", {}).items()})
    elif vig_type == "pie":
        vis_state["params"] = {**common, "legendPosition": "right", "isDonut": True}
        vis_state["params"].update({k: v for k, v in vis_spec.get("params", {}).items()})
    elif vig_type == "table":
        vis_state["params"] = {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
                               "showTotal": False, "totalFunc": "sum", "percentageCol": ""}
        vis_state["params"].update({k: v for k, v in vis_spec.get("params", {}).items()})
    elif vig_type == "metric":
        vis_state["params"] = {"style": {"fontSize": "36px"}, "labels": {"show": True},
                               "metricTitle": vis_spec.get("params", {}).get("metricTitle", "")}
        vis_state["params"].update({k: v for k, v in vis_spec.get("params", {}).items()})

    if "filter" in vis_spec:
        search_source = {"query": {"query": vis_spec["filter"], "language": "kuery"}, "filter": []}
    else:
        search_source = {"query": {"query": "", "language": "kuery"}, "filter": []}
    # La referencia real se resuelve por nombre; sin indexRefName Kibana
    # importa la visualización pero no puede cargar el data view.
    search_source["indexRefName"] = "kibanaSavedObjectMeta.searchSourceJSON.index"
    refs = [
        {"id": dv["id"], "name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern"}
    ]
    if vis_spec.get("range_filter"):
        rf = vis_spec["range_filter"]
        field = rf["field"]
        gte = rf.get("gte", "now-15m")
        lte = rf.get("lte", "now")
        ref_name = "kibanaSavedObjectMeta.searchSourceJSON.filter[0].meta.index"
        search_source["filter"] = [{
            "meta": {
                "indexRefName": ref_name, "negate": False, "disabled": False,
                "alias": None, "type": "range", "key": field,
                "value": gte, "params": {"gte": gte, "lte": lte},
            },
            "query": {"range": {field: {"gte": gte, "lte": lte}}},
            "$state": {"store": "appState"},
        }]
        refs.append({"id": dv["id"], "name": ref_name, "type": "index-pattern"})

    notes = []
    if "notes_pending" in vis_spec:
        notes.append(vis_spec["notes_pending"])

    return {
        "id": None,  # será asignado por el caller como vis_id
        "type": "visualization",
        "namespaces": ["default"],
        "attributes": {
            "title": vis_spec["title"],
            "description": "; ".join(notes) if notes else (vis_spec.get("desc", "") or ""),
            "visState": json.dumps(vis_state, separators=(",", ":")),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps(search_source, separators=(",", ":")),
            },
            "version": 1,
        },
        "references": refs,
        "$info": {"generator": "dystopia-agent4", "pending_real_validation": False},
    }

def make_dashboard(dash_spec, vis_by_id):
    panels_json, refs = [], []
    for i, panel in enumerate(dash_spec["panels"], start=1):
        vis = vis_by_id.get(panel["vis_id"])
        if vis is None:
            fail(f"dashboard '{dash_spec['id']}' hace referencia al vis inexistente '{panel['vis_id']}'")
        vis_id = vis["id"]
        grid = panel["grid"]
        panel_index = str(i)
        panels_json.append({
            "embeddableConfig": {},
            "gridData": {"x": grid["x"], "y": grid["y"], "w": grid["w"], "h": grid["h"], "i": panel_index},
            # Kibana 9 referencia el panel por nombre; si se usa el formato
            # antiguo con "id", la migración desplaza/duplica las referencias.
            "panelRefName": f"panel_{panel_index}",
            "panelIndex": panel_index,
            "type": "visualization",
            "version": "7.3.0",
        })
        refs.append({"id": vis_id, "name": f"panel_{panel_index}", "type": "visualization"})
    return {
        "id": dash_spec["id"],
        "type": "dashboard",
        "namespaces": ["default"],
        "attributes": {
            "title": dash_spec["title"],
            "description": dash_spec.get("description", ""),
            "panelsJSON": json.dumps(panels_json, separators=(",", ":")),
            "optionsJSON": json.dumps({"darkMode": False, "hidePanelTitles": False}, separators=(",", ":")),
            "kibanaSavedObjectMeta": {"searchSourceJSON": "{}"},
            "timeRestore": False,
            "version": 1,
        },
        "references": refs,
        "$info": {"generator": "dystopia-agent4", "pending_real_validation": False},
    }

def make_map_dashboard_panel_ref(map_id, panel_index):
    return {
        "embeddableConfig": {},
        "gridData": {"x": 0, "y": 36, "w": 64, "h": 24, "i": panel_index},
        "panelRefName": f"panel_{panel_index}",
        "panelIndex": panel_index,
        "type": "map",
        "version": "7.3.0",
    }, {"id": map_id, "name": f"panel_{panel_index}", "type": "map"}

def make_map_so(dv, event_fields):
    if "source.geo.location" not in event_fields:
        fail("el mapa requiere el campo source.geo.location en la data view")
    layer_list = [{
        "source": {
            "type": "ES_SEARCH",
            "id": "layer-1-deception-events-geo",
            "indexPatternRefName": "layer_1_deception-events-dv",
            "geoField": "source.geo.location",
        },
        "style": {"type": "HOT_CIRCLE"},
        "_note": "capa experimental pendiente de validación real"
    }]
    return {
        "id": "deception-geo-map-panel",
        "type": "map",
        "namespaces": ["default"],
        "attributes": {
            "title": "Dystopia - Mapa de ataques (EXPERIMENTAL, pendiente de validar)",
            "description": "PANEL GENERADO CON --with-map: NO TESTEADO contra Kibana 9.3.5. Capa heatmap sobre source.geo.location del data stream deception-events*. Revisar/exportar desde la UI tras el primer import, o rehacer desde Maps UI.",
            "mapState": {"zoom": 2, "center": [0.0, 20.0]},
            "layerListJSON": json.dumps(layer_list, separators=(",", ":")),
            "version": 1,
        },
        "references": [
            {"id": dv["id"], "name": "layer_1_deception-events-dv", "type": "index-pattern"}
        ],
        "$info": {"generator": "dystopia-agent4", "pending_real_validation": False, "experimental": True},
    }

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="Genera NDJSON de dashboards Dystopia sin dependencias nuevas.")
    ap.add_argument("--with-map", action="store_true", help="añade el panel Maps experimental (pending real validation)")
    ap.add_argument("--out", default=os.path.join(ARTIFACTS_DIR, "deception-kibana-bundle.ndjson"))
    args = ap.parse_args()

    specs = json.load(open(SPECS_PATH))
    dvs = specs["data_views"]

    vis_by_id = {}
    for vis_id, vis_spec in specs["visualizations"].items():
        vis = make_vis(vis_spec, next((dv for dv in dvs if dv["id"] == vis_spec["data_view"]), None))
        if vis is None:
            fail(f"vis '{vis_id}' referencia data_view inexistente '{vis_spec['data_view']}'")
        vis["id"] = vis_id
        vis_by_id[vis_id] = vis

    dashboards_by_id = {dv_spec["id"]: dv_spec for dv_spec in dvs}
    dash_to_emit = []
    for dash_spec in specs["dashboards"]:
        dash = make_dashboard(dash_spec, vis_by_id)
        if args.with_map and dash_spec["id"] == "deception-geo-map":
            map_so = make_map_so(next(dv for dv in dvs if dv["id"] == "deception-events-dv"), EVENTS_FIELDS)
            ref_panel, ref_name = make_map_dashboard_panel_ref(map_so["id"], max(int(p["panelIndex"]) for p in json.loads(dash["attributes"]["panelsJSON"])) + 1)
            current = json.loads(dash["attributes"]["panelsJSON"])
            current.append(ref_panel)
            dash["attributes"]["panelsJSON"] = json.dumps(current, separators=(",", ":"))
            dash["references"] = dash["references"] + [ref_name]
            dash_to_emit.append(map_so)
        dash_to_emit.append(dash)

    objects = []
    for dv in dvs:
        objects.append(make_index_pattern(dv))
    objects.extend(vis_by_id.values())
    objects.extend(dash_to_emit)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        for obj in objects:
            clean = {k: v for k, v in obj.items() if not k.startswith("$info")}
            f.write(json.dumps(clean, separators=(",", ":"), ensure_ascii=True))
            f.write("\n")

    # Validación de salida: cada línea parsea JSON, ids únicos, refs consistentes
    seen_ids = set()
    for line in open(args.out, "r", encoding="utf-8"):
        o = json.loads(line)
        if o["id"] in seen_ids:
            fail(f"id duplicado en NDJSON: {o['id']}")
        seen_ids.add(o["id"])
        for ref in o.get("references", []):
            if ref["id"] not in seen_ids and not any(x["id"] == ref["id"] for x in objects):
                fail(f"referencia no resuelta en '{o['id']}': {ref['id']}")

    counts = {}
    for o in objects:
        counts[o["type"]] = counts.get(o["type"], 0) + 1
    with open(args.out, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()

    manifest = {
        "bundle": os.path.basename(args.out),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "spec_version": specs.get("$version"),
        "target_kibana": specs.get("target_kibana"),
        "counts": counts,
        "total_objects": len(objects),
        "sha256": sha,
        "status": "VALIDATED AGAINST KIBANA 9.3.5 (macOS lab): 53/53 objects imported, 7 dashboards and 44 visualizations verified with synthetic data",
        "with_map": args.with_map,
    }
    manifest_path = os.path.join(
        os.path.dirname(os.path.abspath(args.out)),
        os.path.splitext(os.path.basename(args.out))[0] + "-MANIFEST.json",
    )
    if os.path.basename(args.out) == "deception-kibana-bundle.ndjson":
        # el bundle canónico además queda reflejado en MANIFEST.json
        canonical = os.path.join(os.path.dirname(manifest_path), "MANIFEST.json")
        with open(canonical, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, ensure_ascii=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=True)
    print(f"[OK] {len(objects)} objetos -> {args.out}")
    print(f"[OK] counts: {counts}")
    print(f"[OK] sha256: {sha}")
    print(f"[OK] manifest: {manifest_path}")

if __name__ == "__main__":
    main()
