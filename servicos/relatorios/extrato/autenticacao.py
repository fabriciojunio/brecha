"""Confere o token que a API principal emite no /v2.

Formato: base64url("clienteId:perfil:expiraEm") + "." + base64url(HMAC-SHA256).
A autenticação aqui não é a falha plantada: as duas versões do serviço exigem o
mesmo token. O que muda entre /v1 e /v2 é o que se faz depois dele.
"""

import base64
import binascii
import hashlib
import hmac
import time
from dataclasses import dataclass

from django.conf import settings


@dataclass(frozen=True)
class Sessao:
    cliente_id: int
    perfil: str


def _decodificar(parte: str) -> bytes:
    return base64.urlsafe_b64decode(parte + "=" * (-len(parte) % 4))


def ler_token(cabecalho: str | None, agora: float | None = None) -> Sessao | None:
    if not cabecalho or not cabecalho.startswith("Bearer "):
        return None
    partes = cabecalho.removeprefix("Bearer ").split(".")
    if len(partes) != 2:
        return None
    try:
        esperada = hmac.new(settings.BRECHA_SEGREDO, partes[0].encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(esperada, _decodificar(partes[1])):
            return None
        cliente_id, perfil, expira = _decodificar(partes[0]).decode().split(":")
        if (agora or time.time()) >= int(expira):
            return None
        return Sessao(int(cliente_id), perfil)
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
