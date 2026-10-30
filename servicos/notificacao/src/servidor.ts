import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { consultarV1, consultarV2, ParceiroInvalido } from "./parceiro.ts";
import { mesclarV1, validarV2, type Objeto, type Preferencias } from "./preferencias.ts";
import { lerToken, type Sessao } from "./token.ts";

export interface Configuracao {
  segredo: Buffer;
  parceiro: string;
}

const TAMANHO_MAXIMO_DO_CORPO = 8 * 1024;

interface Usuario {
  clienteId: number;
  admin?: boolean;
}

const PADRAO: Preferencias = { canal: "push", silencioInicio: 22, silencioFim: 7 };

export function criarServidor(config: Configuracao): Server {
  // No v1 as preferências são objetos comuns e o perfil de administrador é
  // uma propriedade opcional: quem não tem, herda do protótipo.
  const preferenciasV1 = new Map<number, Objeto>();
  const preferenciasV2 = new Map<number, Preferencias>();
  const fila = [{ id: 1, destino: "conta 200", mensagem: "Você recebeu R$ 50,00 (dados simulados)" }];

  async function tratar(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (req.method === "GET" && url.pathname === "/saude") return responder(res, 204);

    const sessao = lerToken(req.headers.authorization, config.segredo);
    if (!sessao) return responder(res, 401, { erro: "não autenticado" });
    const rota = `${req.method} ${url.pathname}`;

    switch (rota) {
      case "PATCH /v1/preferencias": {
        const corpo = await lerCorpo(req);
        if (corpo === null) return responder(res, 400, { erro: "JSON inválido" });
        const atuais = preferenciasV1.get(sessao.clienteId) ?? { ...PADRAO };
        preferenciasV1.set(sessao.clienteId, mesclarV1(atuais, corpo as Objeto));
        return responder(res, 200, preferenciasV1.get(sessao.clienteId));
      }
      case "PATCH /v2/preferencias": {
        const corpo = await lerCorpo(req);
        const novas = corpo === null ? null : validarV2(preferenciasV2.get(sessao.clienteId) ?? PADRAO, corpo);
        if (novas === null) return responder(res, 400, { erro: "preferências inválidas" });
        preferenciasV2.set(sessao.clienteId, novas);
        return responder(res, 200, novas);
      }
      case "GET /v1/admin/fila": {
        // O usuário é montado a cada pedido; "admin" só existe se alguém pôs.
        const usuario: Usuario = { clienteId: sessao.clienteId };
        if (!usuario.admin) return responder(res, 403, { erro: "proibido" });
        return responder(res, 200, fila);
      }
      case "GET /v2/admin/fila": {
        // O perfil vem do token assinado, nunca de propriedade de objeto.
        if (!ehAdmin(sessao)) return responder(res, 403, { erro: "proibido" });
        return responder(res, 200, fila);
      }
      case "GET /v1/titular":
        return responder(res, 200, await consultarV1(config.parceiro, url.searchParams.get("chave") ?? ""));
      case "GET /v2/titular":
        try {
          return responder(res, 200, await consultarV2(config.parceiro, url.searchParams.get("chave") ?? ""));
        } catch (erro) {
          if (erro instanceof ParceiroInvalido) {
            console.warn(JSON.stringify({ nivel: "aviso", mensagem: "resposta do parceiro recusada", motivo: erro.message }));
            return responder(res, 502, { erro: "parceiro indisponível" });
          }
          throw erro;
        }
      default:
        return responder(res, 404, { erro: "não encontrado" });
    }
  }

  return createServer((req, res) => {
    tratar(req, res).catch((erro: unknown) => {
      console.error(JSON.stringify({ nivel: "erro", mensagem: "falha no pedido", erro: String(erro) }));
      if (!res.headersSent) responder(res, 500, { erro: "erro interno" });
    });
  });
}

function ehAdmin(sessao: Sessao): boolean {
  return sessao.perfil === "ADMIN";
}

async function lerCorpo(req: IncomingMessage): Promise<unknown> {
  const pedacos: Buffer[] = [];
  let total = 0;
  for await (const pedaco of req) {
    total += (pedaco as Buffer).length;
    if (total > TAMANHO_MAXIMO_DO_CORPO) return null;
    pedacos.push(pedaco as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(pedacos).toString("utf8"));
  } catch {
    return null;
  }
}

function responder(res: ServerResponse, status: number, corpo?: unknown): void {
  res.statusCode = status;
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Cache-Control", "no-store");
  if (corpo === undefined) {
    res.end();
    return;
  }
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(corpo));
}
