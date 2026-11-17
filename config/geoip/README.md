# GeoIP local

Coloca aquí `GeoLite2-City.mmdb` / `GeoLite2-Country.mmdb` y, si hace falta,
`geoip-overrides.json`.

`geoip-overrides.json` permite corregir o completar IPs que la base MaxMind
no trae (o trae desactualizadas). Tiene prioridad sobre las bases `.mmdb`:

```json
{
  "203.0.113.10": {
    "country_code": "MX",
    "country": "Mexico",
    "subdivision": "Chiapas",
    "subdivision_code": "CHP",
    "city": "Tuxtla Gutierrez",
    "lat": 16.7387,
    "lon": -93.1414,
    "time_zone": "America/Merida"
  },
  "198.51.100.0/24": {
    "country_code": "US",
    "country": "United States",
    "lat": 39.8,
    "lon": -98.6
  }
}
```

- `country_code` es obligatorio para que el mapa agrupe el origen.
- Se admiten claves exactas (`1.2.3.4`) y rangos CIDR (`1.2.3.0/24`).
- Los campos que falten se rellenan con las bases `.mmdb` disponibles.
- El fichero se recarga solo cuando cambia su fecha de modificación; no hace
  falta reiniciar el control.
- En Docker, monta el directorio en `<config>/geoip` (el laboratorio ya monta
  `deploy/local/geoip`); también se lee la copia incluida en la imagen en
  `config/geoip/geoip-overrides.json`.
- Si ninguna base ni override conoce una IP pública, la app genera una
  ubicación aproximada (`country_code: ZZ`, etiqueta “Sin país (aprox.)”) para
  que el origen no desaparezca del mapa. Para corregirla, añade su entrada
  aquí.
