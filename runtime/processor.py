"""Separate notification worker; persistence/rules never wait for notification I/O."""
import argparse
import json
from ipaddress import ip_address
import ssl
import time
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler

from runtime.localfiles import read_private
from runtime.sensor import NoRedirect
from runtime.storage import EventStore


class Notifier:
    def __init__(self, endpoint, ca, token_file):
        url = urlsplit(endpoint)
        if url.scheme != "https" or url.username or url.password or url.query or url.fragment or url.path != "/v1/alerts":
            raise ValueError("exact HTTPS /v1/alerts endpoint required")
        ip_address(url.hostname)
        ctx = ssl.create_default_context(cafile=ca)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ctx), NoRedirect())
        self.endpoint, self.token_file = endpoint, token_file

    def __call__(self, metadata):
        token = read_private(self.token_file, max_bytes=256).decode().strip()
        if not token or "\n" in token or "\r" in token:
            raise ValueError("invalid notification credential")
        request = Request(self.endpoint, data=json.dumps(metadata).encode(), method="POST",
                          headers={"Content-Type": "application/json", "Authorization": "Bearer " + token})
        with self.opener.open(request, timeout=5) as response:
            if response.status not in {200, 202, 204}:
                raise ConnectionError("notification not acknowledged")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--events", required=True)
    p.add_argument("--endpoint")
    p.add_argument("--ca")
    p.add_argument("--token")
    args = p.parse_args()
    if any((args.endpoint, args.ca, args.token)) and not all((args.endpoint, args.ca, args.token)):
        p.error("notification endpoint, CA and token must be provisioned together")
    store = EventStore(args.events)
    sender = Notifier(args.endpoint, args.ca, args.token) if args.endpoint else None
    while True:
        if sender:
            store.deliver_one(sender)
        print(json.dumps({**store.health(), "notification_enabled": sender is not None}), flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
