import datetime
import hmac
import json
import logging

from django.conf import settings
from django.db import connection
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import render
from django.utils.safestring import mark_safe
from django.views.decorators.http import require_GET, require_POST

from .autenticacao import ler_token
from .models import Cliente, Lancamento

log = logging.getLogger(__name__)

TAMANHO_MAXIMO_DA_BUSCA = 50
LIMITE_DE_LINHAS = 200


def _conta_da_sessao(request: HttpRequest) -> int | None:
    sessao = ler_token(request.headers.get("Authorization"))
    if sessao is None:
        return None
    cliente = Cliente.objects.filter(id=sessao.cliente_id).first()
    return cliente.conta if cliente else None


def _nao_autenticado() -> JsonResponse:
    return JsonResponse({"erro": "não autenticado"}, status=401)


# --- v1: como chega a produção quando ninguém revisa ---------------------------


def _buscar_v1(conta: int, busca: str) -> list[dict]:
    # BRECHA-013: a busca entra no SQL por concatenação. Uma aspa fecha o
    # texto, e um UNION traz qualquer tabela do banco na resposta.
    sql = (
        "SELECT data, descricao, valor_centavos FROM extrato_lancamento "
        f"WHERE conta = {conta} AND descricao ILIKE '%{busca}%' ORDER BY data"
    )
    with connection.cursor() as cursor:
        cursor.execute(sql)
        return [{"data": str(d), "descricao": t, "valorCentavos": v} for d, t, v in cursor.fetchall()]


@require_GET
def extrato_v1(request: HttpRequest) -> JsonResponse:
    conta = _conta_da_sessao(request)
    if conta is None:
        return _nao_autenticado()
    return JsonResponse({"lancamentos": _buscar_v1(conta, request.GET.get("busca", ""))})


@require_GET
def extrato_html_v1(request: HttpRequest) -> HttpResponse:
    conta = _conta_da_sessao(request)
    if conta is None:
        return _nao_autenticado()
    lancamentos = _buscar_v1(conta, request.GET.get("busca", ""))
    # BRECHA-014: a descrição foi escrita por quem mandou o dinheiro, e o
    # mark_safe desliga o escape do template "para aceitar negrito".
    for lancamento in lancamentos:
        lancamento["descricao"] = mark_safe(lancamento["descricao"])  # noqa: S308 (falha plantada)
    return render(request, "extrato/extrato.html", {"lancamentos": lancamentos, "versao": "v1"})


# --- v2: corrigido --------------------------------------------------------------


def _buscar_v2(conta: int, busca: str) -> list[dict]:
    # ORM com parâmetros: a busca é dado, nunca SQL. Tamanho e quantidade de
    # linhas limitados.
    consulta = Lancamento.objects.filter(conta=conta, descricao__icontains=busca)[:LIMITE_DE_LINHAS]
    return [
        {"data": str(item.data), "descricao": item.descricao, "valorCentavos": item.valor_centavos}
        for item in consulta
    ]


def _busca_valida(request: HttpRequest) -> str | None:
    busca = request.GET.get("busca", "")
    return busca if len(busca) <= TAMANHO_MAXIMO_DA_BUSCA else None


@require_GET
def extrato_v2(request: HttpRequest) -> JsonResponse:
    conta = _conta_da_sessao(request)
    if conta is None:
        return _nao_autenticado()
    busca = _busca_valida(request)
    if busca is None:
        return JsonResponse({"erro": "busca longa demais"}, status=400)
    return JsonResponse({"lancamentos": _buscar_v2(conta, busca)})


@require_GET
def extrato_html_v2(request: HttpRequest) -> HttpResponse:
    conta = _conta_da_sessao(request)
    if conta is None:
        return _nao_autenticado()
    busca = _busca_valida(request)
    if busca is None:
        return JsonResponse({"erro": "busca longa demais"}, status=400)
    # Escape automático do template ligado. A CSP é a segunda barreira: se um
    # dia algo escapar do escape, script nenhum roda.
    resposta = render(request, "extrato/extrato.html", {"lancamentos": _buscar_v2(conta, busca), "versao": "v2"})
    resposta["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"
    return resposta


# --- comum ----------------------------------------------------------------------


@require_POST
def registrar_lancamento(request: HttpRequest) -> JsonResponse:
    """A API principal avisa cada transferência por aqui, pela rede interna."""
    token = request.headers.get("X-Token-De-Servico", "")
    if not hmac.compare_digest(token.encode(), settings.TOKEN_DE_SERVICO.encode()):
        return JsonResponse({"erro": "não autorizado"}, status=401)
    try:
        dados = json.loads(request.body)
        lancamento = Lancamento(
            conta=int(dados["conta"]),
            data=datetime.date.fromisoformat(dados["data"]),
            descricao=str(dados["descricao"])[:140],
            valor_centavos=int(dados["valorCentavos"]),
        )
    except (ValueError, KeyError, TypeError):
        return JsonResponse({"erro": "lançamento inválido"}, status=400)
    lancamento.save()
    return JsonResponse({"id": lancamento.id}, status=201)


def saude(_request: HttpRequest) -> HttpResponse:
    return HttpResponse(status=204)
