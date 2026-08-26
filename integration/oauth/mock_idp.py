#!/usr/bin/env python3
import argparse
import base64
import json
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class State:
    def __init__(self, issuer, jwks_origin, key, secret, log_path):
        self.issuer = issuer
        self.jwks_origin = jwks_origin
        self.key = key
        self.secret = secret
        self.log_path = log_path
        self.kid = "key-1"
        self.cross_origin = False
        self.lock = threading.Lock()
        self.metadata_requests = 0
        self.jwks_requests = 0
        self.introspection_requests = 0
        self.active_introspection = 0
        self.max_active_introspection = 0
        modulus = subprocess.check_output(
            ["openssl", "rsa", "-in", key, "-noout", "-modulus"], text=True
        ).strip()
        number = int(modulus.split("=", 1)[1], 16)
        self.modulus = b64url(number.to_bytes((number.bit_length() + 7) // 8, "big"))
        self.exponent = b64url((65537).to_bytes(3, "big"))

    def log(self, message):
        with self.lock:
            with open(self.log_path, "a", encoding="utf-8") as log:
                log.write(message + "\n")

    def jwks(self):
        with self.lock:
            kid = self.kid
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "key_ops": ["verify"],
                    "alg": "RS256",
                    "kid": kid,
                    "n": self.modulus,
                    "e": self.exponent,
                }
            ]
        }

    def token(self, kind):
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": ["postgres"],
            "scope": "openid db.connect",
            "sub": "oauth_user",
            "exp": now + 300,
        }
        typ = "at+jwt"
        with self.lock:
            kid = self.kid
        if kind == "expired":
            claims["exp"] = now - 600
        elif kind == "wrong-user":
            claims["sub"] = "someone_else"
        elif kind == "wrong-audience":
            claims["aud"] = "other"
        elif kind == "missing-scope":
            claims["scope"] = "openid"
        elif kind == "wrong-typ":
            typ = "JWT"
        elif kind == "rotated":
            kid = "key-2"
        elif kind == "unknown":
            kid = "missing-key"
        elif kind not in {"good", "bad-signature"}:
            raise ValueError("unknown token kind")

        header = b64url(
            json.dumps(
                {"alg": "RS256", "typ": typ, "kid": kid}, separators=(",", ":")
            ).encode()
        )
        payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode()
        signature = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", self.key],
            input=signing_input,
            check=True,
            capture_output=True,
        ).stdout
        encoded_signature = b64url(signature)
        if kind == "bad-signature":
            encoded_signature = encoded_signature[:-1] + (
                "A" if encoded_signature[-1] != "A" else "B"
            )
        return f"{header}.{payload}.{encoded_signature}"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    @property
    def state(self):
        return self.server.state

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, status, value):
        body = value.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path
        self.state.log(f"GET {path}")
        if path == "/health":
            self.send_text(200, "ok")
        elif path == "/issuer/.well-known/openid-configuration":
            with self.state.lock:
                self.state.metadata_requests += 1
                cross_origin = self.state.cross_origin
            jwks = (
                f"{self.state.jwks_origin}/jwks"
                if cross_origin
                else f"{self.state.issuer}/jwks"
            )
            self.send_json(
                200,
                {
                    "issuer": self.state.issuer,
                    "jwks_uri": jwks,
                    "introspection_endpoint": f"{self.state.issuer}/introspect",
                },
            )
        elif path in {"/issuer/jwks", "/jwks"}:
            with self.state.lock:
                self.state.jwks_requests += 1
            self.send_json(200, self.state.jwks())
        elif path.startswith("/token/"):
            try:
                self.send_text(200, self.state.token(path.rsplit("/", 1)[1]))
            except ValueError:
                self.send_json(404, {"error": "unknown token kind"})
        elif path == "/stats":
            with self.state.lock:
                stats = {
                    "metadata": self.state.metadata_requests,
                    "jwks": self.state.jwks_requests,
                    "introspection": self.state.introspection_requests,
                    "max_active_introspection": self.state.max_active_introspection,
                }
            self.send_json(200, stats)
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        self.state.log(f"POST {path}")
        if path == "/control/rotate":
            with self.state.lock:
                self.state.kid = "key-2"
            self.send_json(200, {"ok": True})
            return
        if path == "/control/cross-origin":
            query = parse_qs(urlparse(self.path).query)
            with self.state.lock:
                self.state.cross_origin = query.get("enabled", ["0"])[0] == "1"
            self.send_json(200, {"ok": True})
            return
        if path != "/issuer/introspect":
            self.send_json(404, {"error": "not found"})
            return

        expected = "Basic " + base64.b64encode(
            f"pgdog:{self.state.secret}".encode()
        ).decode()
        if self.headers.get("Authorization") != expected:
            self.send_json(401, {"error": "invalid_client"})
            return

        length = int(self.headers.get("Content-Length", "0"))
        form = parse_qs(self.rfile.read(length).decode())
        token = form.get("token", [""])[0]
        if form.get("token_type_hint") != ["access_token"]:
            self.send_json(400, {"error": "bad_hint"})
            return

        with self.state.lock:
            self.state.introspection_requests += 1
            self.state.active_introspection += 1
            self.state.max_active_introspection = max(
                self.state.max_active_introspection,
                self.state.active_introspection,
            )
        try:
            if token == "opaque-error":
                self.send_json(500, {"error": "provider_error"})
                return
            if token == "opaque-timeout":
                time.sleep(3)
            response = {
                "active": token != "opaque-inactive",
                "token_type": "Bearer",
                "iss": self.state.issuer,
                "aud": "postgres",
                "scope": "openid db.connect",
                "sub": "oauth_user",
                "exp": int(time.time()) + 300,
            }
            if token == "opaque-wrong-user":
                response["sub"] = "someone_else"
            elif token == "opaque-wrong-audience":
                response["aud"] = "other"
            elif token == "opaque-missing-scope":
                response["scope"] = "openid"
            elif token not in {
                "opaque-good",
                "opaque-inactive",
                "opaque-timeout",
                "opaque-slow",
            }:
                response["active"] = False
            if token == "opaque-slow":
                time.sleep(0.5)
            self.send_json(200, response)
        finally:
            with self.state.lock:
                self.state.active_introspection -= 1

    def log_message(self, _format, *_args):
        return


def server(port, cert, key, state):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    httpd.state = state
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--jwks-port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    issuer = f"https://localhost:{args.port}/issuer"
    jwks_origin = f"https://localhost:{args.jwks_port}"
    state = State(issuer, jwks_origin, args.key, args.secret, args.log)
    secondary = threading.Thread(
        target=server,
        args=(args.jwks_port, args.cert, args.key, state),
        daemon=True,
    )
    secondary.start()
    server(args.port, args.cert, args.key, state)


if __name__ == "__main__":
    main()
