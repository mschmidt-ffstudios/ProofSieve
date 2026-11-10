"""Clients for private EUDI Reference Verifier and Credo wallet APIs."""

import base64
import http.client
import json
import re
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import Encoding

from .checks import _Connector, _PinnedConnection, _connector, _interrupt, _remaining
from .sd_jwt import _json as _strict_jws_json, verify_sd_jwt


_INIT = "/ui/presentations/v2"
_PRESENTATIONS = "/ui/presentations/"
_SD_JWT = "/utilities/validations/sdJwtVc"
_MDOC = "/utilities/validations/msoMdoc/deviceResponse"
_CREDO_TRANSACTIONS = "/internal/proofsieve/wallet/transactions"
_ID = re.compile(r"[A-Za-z0-9_-]{16,128}")
_CLIENT_ID = re.compile(r"x509_hash:[A-Za-z0-9_-]{43}")
_REQUEST_PATH = re.compile(r"/wallet/request\.jwt/[A-Za-z0-9_-]{16,128}")
_CREDO_REQUEST_PATH = re.compile(
    r"/oid4vp/proofsieve/authorization-requests/[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"
)
_GRAPHIC = re.compile(r"[\x21-\x7e]+")
_COMPACT_PRESENTATION = re.compile(
    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}(?:~[A-Za-z0-9_-]+)*"
    r"~[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2}"
)
_DEVICE_RESPONSE = re.compile(r"[A-Za-z0-9_-]+={0,2}")
_MAX_RESPONSE = 256 * 1024
_MAX_PRESENTATION = 192 * 1024
_JSON = "application/json"
_FORM = "application/x-www-form-urlencoded"


class WalletUnavailable(Exception):
    """The verifier did not return a trustworthy protocol response."""


class WalletRejected(Exception):
    """The verifier returned a terminal refusal or failed a presentation check."""


@dataclass(frozen=True)
class WalletTransaction:
    transaction_id: str
    authorization_request_uri: str


def _origin(parts):
    return parts.scheme, parts.hostname, parts.port or 443


def _public_origin(value):
    if not isinstance(value, str) or len(value) > 512 or not _GRAPHIC.fullmatch(value):
        raise ValueError("The wallet-facing verifier origin must be HTTPS.")
    parts = urlsplit(value)
    if (
        parts.scheme != "https" or not parts.hostname or parts.username is not None
        or parts.password is not None or parts.port == 0 or parts.path not in {"", "/"}
        or re.search(r"[\\%?#]", value)
    ):
        raise ValueError("The wallet-facing verifier origin must be a bare HTTPS origin.")
    return _origin(parts)


def _response_json(response):
    from .guard import load_json

    headers = response.headers
    lengths = headers.get_all("Content-Length", [])
    encodings = headers.get_all("Transfer-Encoding", [])
    if (
        len(headers.get_all("Content-Type", [])) != 1 or headers.get_content_type() != _JSON
        or headers.get_all("Content-Encoding", []) or lengths and encodings
    ):
        raise WalletUnavailable("wallet_response_invalid")
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,6}", lengths[0]):
            raise WalletUnavailable("wallet_response_invalid")
        size = int(lengths[0])
        if not 0 < size <= _MAX_RESPONSE:
            raise WalletUnavailable("wallet_response_invalid")
        body = response.read(size)
        if len(body) != size:
            raise WalletUnavailable("wallet_response_invalid")
    elif len(encodings) == 1 and encodings[0].lower() == "chunked":
        body = response.read(_MAX_RESPONSE + 1)
        if not 0 < len(body) <= _MAX_RESPONSE:
            raise WalletUnavailable("wallet_response_invalid")
    else:
        raise WalletUnavailable("wallet_response_invalid")
    try:
        return load_json(body)
    except ValueError:
        raise WalletUnavailable("wallet_response_invalid") from None


@dataclass(frozen=True)
class WalletConnector:
    _connector: _Connector = field(repr=False)
    _wallet_origin: tuple[str, str, int]
    client_id: str
    _request_path = _REQUEST_PATH

    def _request(self, method, path, *, body=None, media_type=None, read_bad_request=False, deadline=None):
        target = self._connector
        deadline = time.monotonic() + target.timeout if deadline is None else deadline
        headers = {"Accept": _JSON, "Authorization": f"Bearer {target.token}", "Connection": "close"}
        if media_type:
            headers["Content-Type"] = media_type
        connection = None
        try:
            connection = _PinnedConnection(target.host, target.port, target.ip, target.context, _remaining(deadline))
            connection.connect()
            timeout = _remaining(deadline)
            connection.sock.settimeout(timeout)
            timer = threading.Timer(timeout, _interrupt, args=(connection.sock,))
            timer.daemon = True
            timer.start()
            try:
                connection.request(method, path, body=body, headers=headers)
                with connection.getresponse() as response:
                    read_json = response.status == 200 or (read_bad_request and response.status == 400)
                    payload = _response_json(response) if read_json else None
                    return response.status, payload, response.headers
            finally:
                timer.cancel()
        except (OSError, http.client.HTTPException):
            raise WalletUnavailable("wallet_verifier_unavailable") from None
        finally:
            if connection is not None:
                connection.close()

    def _authorization_uri(self, value, request_uri):
        if not all(isinstance(uri, str) and len(uri) <= 4096 and _GRAPHIC.fullmatch(uri)
                   for uri in (value, request_uri)):
            raise WalletUnavailable("wallet_request_uri_invalid")
        try:
            request = urlsplit(request_uri)
            auth = urlsplit(value)
            expected = {"client_id": self.client_id, "request_uri": request_uri, "request_uri_method": "get"}
            parameters = parse_qsl(auth.query, strict_parsing=True, max_num_fields=3, errors="strict")
            if (
                _origin(request) != self._wallet_origin or request.username is not None
                or request.password is not None or re.search(r"[\\%?#]", request_uri)
                or not self._request_path.fullmatch(request.path)
                or auth.scheme != "haip-vp" or auth.netloc or auth.path or "#" in value
                or not value.startswith("haip-vp://?") or len(parameters) != 3 or dict(parameters) != expected
            ):
                raise WalletUnavailable("wallet_request_uri_invalid")
        except ValueError:
            raise WalletUnavailable("wallet_request_uri_invalid") from None
        return value

    def start(self, *, profile, nonce):
        if not isinstance(nonce, str) or not _ID.fullmatch(nonce):
            raise ValueError("Invalid wallet transaction nonce.")
        body = {
            "dcql_query": profile.dcql_query,
            "nonce": nonce,
            "response_mode": "direct_post.jwt",
            "jar_mode": "by_reference",
            "request_uri_method": "get",
            "authorization_request_scheme": "haip-vp",
            "profile": "haip",
            "issuer_chain": profile.issuer_chain,
            "intended_use_id": profile.intended_use_id,
        }
        status, payload, headers = self._request("POST", _INIT, body=json.dumps(body).encode(), media_type=_JSON)
        if (
            status != 200 or type(payload) is not dict or payload.keys() != {
                "transaction_id", "client_id", "request_uri", "request_uri_method", "authorization_request_uri",
            }
            or payload["client_id"] != self.client_id or payload["request_uri_method"] != "get"
            or not isinstance(payload["transaction_id"], str) or not _ID.fullmatch(payload["transaction_id"])
            or headers.get_all("Transaction-Id", []) != [payload["transaction_id"]]
            or headers.get_all("Authorization-Request-Uri", []) != [payload["authorization_request_uri"]]
        ):
            raise WalletUnavailable("wallet_transaction_invalid")
        return WalletTransaction(
            payload["transaction_id"], self._authorization_uri(payload["authorization_request_uri"], payload["request_uri"])
        )

    def result(self, *, transaction_id, profile, nonce):
        if (
            not isinstance(transaction_id, str) or not _ID.fullmatch(transaction_id)
            or not isinstance(nonce, str) or not _ID.fullmatch(nonce)
        ):
            raise ValueError("Invalid wallet transaction reference.")
        deadline = time.monotonic() + self._connector.timeout
        status, payload, _ = self._request(
            "GET", _PRESENTATIONS + transaction_id, read_bad_request=True, deadline=deadline
        )
        if status == 400 and payload == {"error": "PresentationNotSubmitted"}:
            return None
        if status != 200 or type(payload) is not dict:
            raise WalletUnavailable("wallet_transaction_result_invalid")
        if (payload.keys() in ({"error"}, {"error", "error_description"})
                and isinstance(payload["error"], str) and payload["error"]
                and isinstance(payload.get("error_description", ""), str)):
            raise WalletRejected("wallet_presentation_refused")
        presentation = self._presentation(payload, profile.format)
        if profile.format == "dc+sd-jwt":
            route = _SD_JWT
            form = {"sd_jwt_vc": presentation, "nonce": nonce, "audience": self.client_id}
        else:
            # The transaction GET above only releases submitted, DeviceAuth- and session-checked
            # responses. The mdoc utility supplies a verified JSON projection of that same response.
            route = _MDOC
            form = {"device_response": presentation}
        form["issuer_chain"] = profile.issuer_chain
        status, verified, _ = self._request(
            "POST", route, body=urlencode(form).encode("ascii"), media_type=_FORM, deadline=deadline
        )
        if status == 400:
            raise WalletRejected("wallet_presentation_validation_failed")
        if status != 200:
            raise WalletUnavailable("wallet_presentation_result_invalid")
        return self._project(profile, verified, presentation)

    @staticmethod
    def _presentation(payload, format):
        if payload.keys() != {"vp_token"}:
            raise WalletUnavailable("wallet_presentation_result_invalid")
        token = payload["vp_token"]
        if type(token) is not dict or token.keys() != {"credential"}:
            raise WalletUnavailable("wallet_presentation_result_invalid")
        candidates = token["credential"]
        if type(candidates) is not list or len(candidates) != 1:
            raise WalletUnavailable("wallet_presentation_result_invalid")
        return WalletConnector._validate_presentation(candidates[0], format)

    @staticmethod
    def _validate_presentation(candidate, format):
        if not isinstance(candidate, str) or not 0 < len(candidate) <= _MAX_PRESENTATION:
            raise WalletUnavailable("wallet_presentation_result_invalid")
        patterns = {"dc+sd-jwt": _COMPACT_PRESENTATION, "mso_mdoc": _DEVICE_RESPONSE}
        if format not in patterns or not patterns[format].fullmatch(candidate):
            raise WalletRejected("wallet_presentation_serialization_unsupported")
        return candidate

    @staticmethod
    def _project(profile, verified, presentation):
        try:
            return profile.project(verified, presentation=presentation)
        except ValueError:
            raise WalletRejected("wallet_presentation_claims_invalid") from None


class CredoWalletConnector(WalletConnector):
    """Use the Credo bridge's verified result with the same local claim and status policy."""

    _request_path = _CREDO_REQUEST_PATH

    def start(self, *, profile, nonce):
        if not isinstance(nonce, str) or not _ID.fullmatch(nonce):
            raise ValueError("Invalid wallet transaction nonce.")
        body = {
            "dcql_query": profile.dcql_query,
            "nonce": nonce,
            "issuer_chain": profile.issuer_chain,
            "intended_use_id": profile.intended_use_id,
        }
        status, payload, _ = self._request(
            "POST", _CREDO_TRANSACTIONS, body=json.dumps(body).encode(), media_type=_JSON
        )
        if (
            status != 200 or type(payload) is not dict
            or payload.keys() != {"transaction_id", "nonce", "client_id", "request_uri"}
            or payload["nonce"] != nonce or payload["client_id"] != self.client_id
            or not isinstance(payload["transaction_id"], str) or not _ID.fullmatch(payload["transaction_id"])
            or not isinstance(payload["request_uri"], str) or len(payload["request_uri"]) > 4096
        ):
            raise WalletUnavailable("wallet_transaction_invalid")
        request_uri = payload["request_uri"]
        authorization_uri = "haip-vp://?" + urlencode({
            "client_id": self.client_id, "request_uri": request_uri, "request_uri_method": "get",
        })
        return WalletTransaction(payload["transaction_id"], self._authorization_uri(authorization_uri, request_uri))

    def result(self, *, transaction_id, profile, nonce):
        if (
            not isinstance(transaction_id, str) or not _ID.fullmatch(transaction_id)
            or not isinstance(nonce, str) or not _ID.fullmatch(nonce)
        ):
            raise ValueError("Invalid wallet transaction reference.")
        status, payload, _ = self._request("GET", f"{_CREDO_TRANSACTIONS}/{transaction_id}")
        if (
            status != 200 or type(payload) is not dict or payload.get("transaction_id") != transaction_id
            or payload.get("nonce") != nonce or payload.get("client_id") != self.client_id
        ):
            raise WalletUnavailable("wallet_transaction_result_invalid")
        state = payload.get("state")
        common = {"transaction_id", "nonce", "client_id", "state"}
        if payload.keys() == common:
            if state == "pending":
                return None
            if state == "rejected":
                raise WalletRejected("wallet_presentation_refused")
        verified_type = dict if profile.format == "dc+sd-jwt" else list
        if (
            state != "verified" or payload.keys() != common | {"format", "presentation", "verified"}
            or payload["format"] != profile.format or type(payload["verified"]) is not verified_type
        ):
            raise WalletUnavailable("wallet_presentation_result_invalid")
        try:
            presentation = self._validate_presentation(payload["presentation"], profile.format)
        except WalletRejected:
            raise WalletUnavailable("wallet_presentation_result_invalid") from None
        verified = payload["verified"]
        if profile.format == "dc+sd-jwt":
            verified = _verify_credo_sd_jwt(presentation, issuer=profile.issuer)
        return self._project(profile, verified, presentation)


def _verify_credo_sd_jwt(presentation, *, issuer):
    # Credo authenticates the holder and X.509 chain. Recheck the exact issuer
    # JWS and every supplied disclosure before giving the claims to a rule.
    issuer_and_disclosures, _, _holder_proof = presentation.rpartition("~")
    try:
        header = _strict_jws_json(issuer_and_disclosures.split(".", 1)[0])
        chain = header.get("x5c") if type(header) is dict else None
        if (type(chain) is not list or not 1 <= len(chain) <= 8
                or any(type(entry) is not str or not 1 <= len(entry) <= 16_384 for entry in chain)):
            raise ValueError("Expected an X.509 issuer certificate chain.")
        leaf_der = base64.b64decode(chain[0], validate=True)
        if base64.b64encode(leaf_der).decode("ascii") != chain[0]:
            raise ValueError("Expected a canonical x5c leaf.")
        leaf = x509.load_der_x509_certificate(leaf_der)
        if leaf.public_bytes(Encoding.DER) != leaf_der:
            raise ValueError("Unexpected content after the x5c leaf.")
        return verify_sd_jwt(
            issuer_and_disclosures + "~", leaf.public_key(), issuer=issuer, now=datetime.now(timezone.utc),
        )
    except (ValueError, UnsupportedAlgorithm):
        raise WalletRejected("wallet_presentation_validation_failed") from None


def load_wallet_connector(config):
    """Bind an operator's fixed private HTTPS route and public wallet endpoint."""
    required = {"url", "allowedNetworks", "bearerEnv", "publicOrigin", "clientId"}
    optional = {"caFile", "timeoutSeconds", "kind"}
    if type(config) is not dict or not required <= config.keys() or config.keys() - required - optional:
        raise ValueError("A wallet connector needs URL, network, bearer, public origin and client ID settings.")
    kind = config.get("kind", "eudi")
    if kind not in ("eudi", "credo"):
        raise ValueError("Wallet connector kind must be eudi or credo.")
    client_id = config["clientId"]
    if not isinstance(client_id, str) or not _CLIENT_ID.fullmatch(client_id):
        raise ValueError("The wallet connector clientId must use the HAIP x509_hash scheme.")
    wallet_origin = _public_origin(config["publicOrigin"])
    transport = {key: value for key, value in config.items() if key not in {"publicOrigin", "clientId", "kind"}}
    if not isinstance(transport["url"], str):
        raise ValueError("The private wallet connector URL must be an HTTPS origin.")
    transport["url"] = transport["url"].rstrip("/") + "/"
    target = _connector({**transport, "kind": "remote"})
    if target.path != "/":
        raise ValueError("The private wallet connector URL must be an HTTPS origin.")
    implementation = CredoWalletConnector if kind == "credo" else WalletConnector
    return implementation(target, wallet_origin, client_id)
