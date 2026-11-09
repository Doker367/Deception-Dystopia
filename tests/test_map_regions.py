"""Check the checked-in admin-1 assets and two city-to-subdivision mappings."""

import json
from pathlib import Path

import pytest

REGIONS = Path(__file__).resolve().parents[1] / "web" / "public" / "regions"


def _inside_ring(lon: float, lat: float, ring: list[list[float]]) -> bool:
    inside = False
    for index, (x1, y1) in enumerate(ring):
        x2, y2 = ring[index - 1]
        if (y1 > lat) != (y2 > lat) and lon < x1 + (lat - y1) * (x2 - x1) / (y2 - y1):
            inside = not inside
    return inside


def _covers(feature: dict, lon: float, lat: float) -> bool:
    geometry = feature["geometry"]
    polygons = [geometry["coordinates"]] if geometry["type"] == "Polygon" else geometry["coordinates"]
    return any(_inside_ring(lon, lat, rings[0]) and not any(
        _inside_ring(lon, lat, hole) for hole in rings[1:]
    ) for rings in polygons)


@pytest.mark.parametrize(
    ("country", "expected_count", "point", "expected_code"),
    [
        ("mx", 32, (-103.3496, 20.6597), "JAL"),  # Guadalajara
        ("ca", 13, (-79.3832, 43.6532), "ON"),  # Toronto
    ],
)
def test_city_belongs_to_exactly_one_admin1(country, expected_count, point, expected_code):
    collection = json.loads((REGIONS / f"{country}.geo.json").read_text(encoding="utf-8"))
    assert collection["type"] == "FeatureCollection"
    features = collection["features"]
    assert len(features) == expected_count
    codes = [feature["properties"]["code"] for feature in features]
    assert len(set(codes)) == expected_count
    for feature in features:
        assert feature["type"] == "Feature"
        assert set(feature["properties"]) == {"code", "name"}
        assert feature["properties"]["name"]
        assert feature["geometry"]["type"] in {"Polygon", "MultiPolygon"}
        assert feature["properties"]["code"].isalnum()  # ISO 3166-2, sin prefijo
    assert [feature["properties"]["code"] for feature in features if _covers(feature, *point)] == [expected_code]
