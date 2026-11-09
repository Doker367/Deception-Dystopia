"""Regenerate the checked-in MX/CA admin-1 GeoJSON from Natural Earth (public domain).

Run from the repository root: .venv/bin/python scripts/build_map_regions.py
The source revision and licenses are documented in LICENSES-THIRD-PARTY.md.
"""

import json
from pathlib import Path
from urllib.request import urlopen

SOURCE = "https://raw.githubusercontent.com/nvkelso/natural-earth-vector/ca96624a56bd078437bca8184e78163e5039ad19/geojson/"
OUTPUT = Path(__file__).resolve().parents[1] / "web" / "public" / "regions"

# Natural Earth 50m contains all 13 Canadian provinces/territories, but does
# not include Mexico's admin-1 polygons; Mexico therefore needs the 10m layer.
COUNTRIES = {"ca": ("50m", 13), "mx": ("10m", 32)}


def build(country: str, resolution: str, expected_count: int) -> None:
    url = f"{SOURCE}ne_{resolution}_admin_1_states_provinces.geojson"
    with urlopen(url, timeout=90) as response:
        source = json.load(response)

    features = []
    for feature in source["features"]:
        props = feature["properties"]
        if props.get("iso_a2") != country.upper():
            continue
        full_code = props.get("iso_3166_2")
        # The 10m MX layer also contains an unassigned minor island (MX-X01~).
        # It has no ISO 3166-2 subdivision code or name and is not an admin-1.
        if full_code == "MX-X01~":
            continue
        if not isinstance(full_code, str) or not full_code.startswith(f"{country.upper()}-"):
            raise ValueError(f"Missing ISO 3166-2 code: {full_code!r}")
        code = full_code.split("-", 1)[1]
        name = props.get("name")
        if country == "mx" and code == "DIF":
            # Natural Earth's old Distrito Federal code predates MX-CMX (2016).
            code, name = "CMX", "Ciudad de México"
        if not isinstance(name, str) or not name or not code.isalnum():
            raise ValueError(f"Invalid admin-1 name/code: {name!r}, {code!r}")
        geometry = feature["geometry"]
        if geometry["type"] not in ("Polygon", "MultiPolygon"):
            raise ValueError(f"Invalid geometry: {geometry['type']!r}")
        features.append({"type": "Feature", "properties": {"code": code, "name": name}, "geometry": geometry})

    codes = {feature["properties"]["code"] for feature in features}
    if len(features) != expected_count or len(codes) != expected_count:
        raise ValueError(f"Incomplete {country.upper()} admin-1 set: {len(features)} features, {len(codes)} codes")
    features.sort(key=lambda feature: feature["properties"]["code"])
    OUTPUT.mkdir(parents=True, exist_ok=True)
    target = OUTPUT / f"{country}.geo.json"
    target.write_text(json.dumps({"type": "FeatureCollection", "features": features}, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"{target.relative_to(OUTPUT.parents[2])}: {len(features)} regions ({target.stat().st_size:,} bytes)")


if __name__ == "__main__":
    for iso2, (scale, count) in COUNTRIES.items():
        build(iso2, scale, count)
