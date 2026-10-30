"""Control-side transport for the process-credentialled Unix metadata bridge.

No SQLite connection or sensor credential exists in the control process.
"""
import json
import os
from pathlib import Path
import re
import socket
import struct

SOCKET_PATH = Path(os.environ["DYSTOPIA_QUERY_SOCKET"]) if os.getenv("DYSTOPIA_QUERY_SOCKET") else None
MAX_RESPONSE = 512 * 1024
ALLOWED_ITEM = {"sensor", "event_id", "device", "received_at", "observed_at", "kind", "source", "proto"}
ERROR_CODES = {"INVALID": 422, "LIMIT": 422, "DENIED": 503, "BUSY": 503, "UNAVAILABLE": 503, "NOT_FOUND": 404}


class BridgeError(Exception):
    def __init__(self, status, error_id=None):
        super().__init__("Query service unavailable" if status >= 500 else "Invalid or limited query")
        self.status = status
        self.error_id = error_id


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate bridge field")
        result[key] = value
    return result


def _reject_constant(_):
    raise ValueError("non-finite bridge value")


def _exact(conn, size):
    chunks = bytearray()
    while len(chunks) < size:
        part = conn.recv(size - len(chunks))
        if not part:
            raise BridgeError(503)
        chunks.extend(part)
    return bytes(chunks)


def query(operation, **params):
    if SOCKET_PATH is None or not SOCKET_PATH.is_absolute():
        raise BridgeError(503)
    body = json.dumps({"version": 1, "operation": operation, **params}, separators=(",", ":"), allow_nan=False).encode()
    if len(body) > 4096:
        raise BridgeError(422)
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
            conn.settimeout(1.5)
            conn.connect(str(SOCKET_PATH))
            conn.sendall(struct.pack("!I", len(body)) + body)
            length = struct.unpack("!I", _exact(conn, 4))[0]
            if not 0 < length <= MAX_RESPONSE:
                raise BridgeError(503)
            result = json.loads(_exact(conn, length), object_pairs_hook=_unique_pairs,
                                parse_constant=_reject_constant)
    except (OSError, UnicodeError, ValueError, TypeError):
        raise BridgeError(503) from None
    if not isinstance(result, dict) or type(result.get("version")) is not int or result["version"] != 1:
        raise BridgeError(503)
    if "error" in result:
        if set(result) != {"version", "error", "id"}:
            raise BridgeError(503)
        identifier = result.get("id")
        if not isinstance(identifier, str) or re.fullmatch(r"[a-f0-9]{16}", identifier) is None:
            identifier = None
        code = result["error"] if isinstance(result["error"], str) else "UNAVAILABLE"
        raise BridgeError(ERROR_CODES.get(code, 503), identifier)
    if operation in {"list", "export"}:
        if (set(result) != {"version", "items", "total", "offset", "limit", "next_cursor",
                            "truncated", "received_from", "received_to", "queried_at", "redacted"}
                or result.get("redacted") is not True or not isinstance(result.get("items"), list)
                or len(result["items"]) > (100 if operation == "list" else 500)
                or type(result.get("total")) is not int or result["total"] < 0
                or type(result.get("offset")) is not int or not 0 <= result["offset"] <= 10000
                or type(result.get("limit")) is not int or type(result.get("truncated")) is not bool
                or not all(isinstance(result.get(key), str) and len(result[key]) <= 40
                           for key in ("received_from", "received_to", "queried_at"))
                or not (result.get("next_cursor") is None or isinstance(result["next_cursor"], str)
                        and len(result["next_cursor"]) <= 1024)
                or not all(isinstance(row, dict) and set(row) == ALLOWED_ITEM
                           and all(isinstance(value, str) and len(value) <= 64
                                   for value in row.values()) for row in result["items"])):
            raise BridgeError(503)
    elif operation == "detail":
        event = result.get("event")
        if (set(result) != {"version", "event", "redacted"} or result.get("redacted") is not True
                or not isinstance(event, dict) or set(event) != ALLOWED_ITEM
                or not all(isinstance(value, str) and len(value) <= 64 for value in event.values())):
            raise BridgeError(503)
    elif operation == "activity":
        if (set(result) != {"version", "unit", "minutes", "queried_at", "buckets"}
                or result.get("unit") != "events/minute"
                or type(result.get("minutes")) is not int or not 5 <= result["minutes"] <= 1440
                or not isinstance(result.get("queried_at"), str) or len(result["queried_at"]) > 40
                or not isinstance(result.get("buckets"), list)
                or len(result["buckets"]) != result["minutes"]
                or not all(isinstance(bucket, dict) and set(bucket) == {"at", "count"}
                           and isinstance(bucket["at"], str) and len(bucket["at"]) <= 40
                           and type(bucket["count"]) is int and 0 <= bucket["count"] <= 100000
                           for bucket in result["buckets"])):
            raise BridgeError(503)
    else:
        raise BridgeError(503)
    return result
