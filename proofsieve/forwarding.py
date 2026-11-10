"""Deliver an approved verification request to an operator-configured HTTPS route."""

import http.client
import re
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from .checks import _Connector, _PinnedConnection, _connector, _interrupt, _remaining


_DELIVERY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_REQUIRED_FIELDS = {"url", "allowedNetworks", "bearerEnv"}
_OPTIONAL_FIELDS = {"caFile", "timeoutSeconds"}


class ForwardingUnavailable(Exception):
    """The target may have received the request, but no terminal status was obtained."""


@dataclass(frozen=True)
class ForwardingTarget:
    _connector: _Connector = field(repr=False)

    def send(self, raw_body: bytes, delivery_id: str) -> int:
        from .guard import MAX_BODY_BYTES

        if type(raw_body) is not bytes or not 0 < len(raw_body) <= MAX_BODY_BYTES:
            raise ValueError("Forwarding requires the bounded original request body.")
        if not isinstance(delivery_id, str) or not _DELIVERY_ID.fullmatch(delivery_id):
            raise ValueError("Forwarding requires a valid delivery identifier.")

        target = self._connector
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {target.token}",
            "Idempotency-Key": delivery_id,
            "Connection": "close",
        }
        deadline = time.monotonic() + target.timeout
        connection = _PinnedConnection(target.host, target.port, target.ip, target.context, target.timeout)
        try:
            connection.connect()
            timeout = _remaining(deadline)
            connection.sock.settimeout(timeout)
            # Apply one deadline to the entire write and response-header read.
            timer = threading.Timer(timeout, _interrupt, args=(connection.sock,))
            timer.daemon = True
            timer.start()
            try:
                connection.request("POST", target.path, body=raw_body, headers=headers)
                with connection.getresponse() as response:
                    if 200 <= response.status <= 599:
                        return response.status
                    raise ForwardingUnavailable("forwarding_status_unavailable")
            finally:
                timer.cancel()
        except (OSError, http.client.HTTPException) as exc:
            raise ForwardingUnavailable("forwarding_status_unavailable") from exc
        finally:
            connection.close()


def load_forwarding(path) -> dict[str, ForwardingTarget]:
    """Load exact source routes and resolve their fixed HTTPS destinations at startup."""
    from .access import _read_config
    from .guard import MAX_ENDPOINTS, load_json, validate_endpoint

    try:
        raw = _read_config(Path(path))
    except ValueError:
        raise ValueError("Forwarding configuration must be a bounded owner-only regular file.") from None
    try:
        config = load_json(raw)
    except ValueError:
        raise ValueError("Invalid JSON in forwarding configuration.") from None
    if (type(config) is not dict or config.keys() != {"version", "endpoints"}
            or type(config["version"]) is not int or config["version"] != 1
            or type(config["endpoints"]) is not dict or len(config["endpoints"]) > MAX_ENDPOINTS):
        raise ValueError("Forwarding configuration requires version 1 and exact endpoints.")

    targets = {}
    for endpoint, settings in config["endpoints"].items():
        validate_endpoint(endpoint)
        if (type(settings) is not dict or not _REQUIRED_FIELDS <= settings.keys()
                or settings.keys() - _REQUIRED_FIELDS - _OPTIONAL_FIELDS):
            raise ValueError("Forwarding target requires url, allowedNetworks and bearerEnv.")
        targets[endpoint] = ForwardingTarget(_connector({**settings, "kind": "remote"}))
    return targets
