// Exploração no /v1 e bloqueio no /v2, por HTTP de verdade. Dados simulados.

import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { after, afterEach, before, describe, test } from "node:test";
import { criarServidor } from "../src/servidor.ts";

const SEGREDO = Buffer.from("laboratorio-local-segredo-com-mais-de-32-bytes");

function token(clienteId: number, perfil = "CLIENTE", validadeSegundos = 900): string {
  const conteudo = Buffer.from(`${clienteId}:${perfil}:${Math.floor(Date.now() / 1000) + validadeSegundos}`).toString("base64url");
  const assinatura = createHmac("sha256", SEGREDO).update(conteudo).digest("base64url");
  return `Bearer ${conteudo}.${assinatura}`;
}

const ANA = token(1);
const OPERACAO = token(3, "ADMIN");

function subir(servidor: Server): Promise<string> {
  return new Promise((resolver) => {
    servidor.listen(0, "127.0.0.1", () => resolver(`http://127.0.0.1:${(servidor.address() as AddressInfo).port}`));
  });
}

// O serviço interno que o parceiro comprometido manda buscar.
const interno = createServer((_req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ painel: "interno", segredoDoBanco: "senha-do-banco-de-laboratorio" }));
});

// O parceiro: responde normal para uma chave, redireciona para o interno na
// outra e manda resposta enorme ou fora do formato nas demais.
let enderecoInterno = "";
const parceiro = createServer((req, res) => {
  const chave = decodeURIComponent((req.url ?? "").split("/").pop() ?? "");
  if (chave === "ana@exemplo.com.br") {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ nome: "Ana Souza", banco: "Banco Brecha" }));
  } else if (chave === "redireciona") {
    res.writeHead(302, { Location: `${enderecoInterno}/segredos` }).end();
  } else if (chave === "enorme") {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ nome: "x".repeat(50_000), banco: "y" }));
  } else {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ nome: { $gt: "" }, banco: "Banco", html: "<script>alert(1)</script>" }));
  }
});

let base = "";
const notificacao = { servidor: undefined as Server | undefined };

before(async () => {
  enderecoInterno = await subir(interno);
  const enderecoParceiro = await subir(parceiro);
  notificacao.servidor = criarServidor({ segredo: SEGREDO, parceiro: enderecoParceiro });
  base = await subir(notificacao.servidor);
});

after(() => {
  for (const s of [interno, parceiro, notificacao.servidor]) s?.close();
});

async function pedir(caminho: string, autorizacao?: string, corpo?: unknown): Promise<{ status: number; json: any }> {
  const resposta = await fetch(base + caminho, {
    method: corpo === undefined ? "GET" : "PATCH",
    headers: { ...(autorizacao ? { Authorization: autorizacao } : {}), "Content-Type": "application/json" },
    ...(corpo === undefined ? {} : { body: typeof corpo === "string" ? corpo : JSON.stringify(corpo) }),
  });
  const texto = await resposta.text();
  return { status: resposta.status, json: texto ? JSON.parse(texto) : null };
}

describe("autenticação", () => {
  test("sem token, com token forjado ou vencido responde 401", async () => {
    const forjado = `Bearer ${Buffer.from("3:ADMIN:9999999999").toString("base64url")}.${"A".repeat(43)}`;
    for (const cabecalho of [undefined, "Bearer lixo", forjado, token(1, "CLIENTE", -1)]) {
      assert.equal((await pedir("/v2/admin/fila", cabecalho)).status, 401);
    }
  });
});

describe("BRECHA-016: poluição de protótipo nas preferências", () => {
  afterEach(() => {
    // A poluição vale para o processo inteiro; limpar para não vazar no próximo teste.
    delete (Object.prototype as Record<string, unknown>).admin;
  });

  test("v1: a Ana vira administradora mandando __proto__ nas preferências", async () => {
    assert.equal((await pedir("/v1/admin/fila", ANA)).status, 403);
    const resposta = await pedir("/v1/preferencias", ANA, '{"canal":"sms","__proto__":{"admin":true}}');
    assert.equal(resposta.status, 200);
    const fila = await pedir("/v1/admin/fila", ANA);
    assert.equal(fila.status, 200);
    assert.match(JSON.stringify(fila.json), /Você recebeu/);
  });

  test("v2: ignora __proto__, aceita só os campos conhecidos e não dá administração", async () => {
    const resposta = await pedir("/v2/preferencias", ANA, '{"canal":"sms","__proto__":{"admin":true}}');
    assert.equal(resposta.status, 200);
    assert.deepEqual(resposta.json, { canal: "sms", silencioInicio: 22, silencioFim: 7 });
    assert.equal(({} as Record<string, unknown>).admin, undefined);
    assert.equal((await pedir("/v2/admin/fila", ANA)).status, 403);
    assert.equal((await pedir("/v2/admin/fila", OPERACAO)).status, 200);
  });

  test("v2: recusa valor fora do esperado", async () => {
    for (const corpo of [{ canal: "telegrama" }, { silencioInicio: 25 }, { silencioFim: "7" }, ["canal"], "nada"]) {
      assert.equal((await pedir("/v2/preferencias", ANA, corpo)).status, 400, JSON.stringify(corpo));
    }
  });
});

describe("BRECHA-015: consumo inseguro da API do parceiro", () => {
  test("v1: segue o redirecionamento do parceiro e devolve o serviço interno", async () => {
    const resposta = await pedir("/v1/titular?chave=redireciona", ANA);
    assert.equal(resposta.status, 200);
    assert.equal(resposta.json.segredoDoBanco, "senha-do-banco-de-laboratorio");
  });

  test("v1: repassa o que o parceiro mandar, até campo que ninguém pediu", async () => {
    const resposta = await pedir("/v1/titular?chave=outra", ANA);
    assert.equal(resposta.json.html, "<script>alert(1)</script>");
  });

  test("v2: o caminho normal devolve só nome e banco", async () => {
    const resposta = await pedir("/v2/titular?chave=ana%40exemplo.com.br", ANA);
    assert.deepEqual(resposta.json, { nome: "Ana Souza", banco: "Banco Brecha" });
  });

  test("v2: recusa redirecionamento, resposta enorme e formato inesperado", async () => {
    for (const chave of ["redireciona", "enorme", "outra"]) {
      const resposta = await pedir(`/v2/titular?chave=${chave}`, ANA);
      assert.equal(resposta.status, 502, chave);
      assert.doesNotMatch(JSON.stringify(resposta.json), /senha-do-banco/);
    }
  });

  test("v2: recusa chave com caractere que mudaria o caminho no parceiro", async () => {
    assert.equal((await pedir("/v2/titular?chave=..%2F..%2Fadmin", ANA)).status, 502);
  });
});
