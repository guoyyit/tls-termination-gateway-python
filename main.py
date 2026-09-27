"""Service entry.

Keeps the original plaintext FastAPI listener intact and additionally
exposes the TLS termination gateway via :func:`tls_gateway.server.main`.
"""

from __future__ import annotations

import sys

from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


if __name__ == "__main__":
    from tls_gateway.server import main as gateway_main

    gateway_main(sys.argv[1] if len(sys.argv) > 1 else "gateway.toml")
