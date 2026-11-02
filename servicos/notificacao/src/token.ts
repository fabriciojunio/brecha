// Confere o token que a API principal emite no /v2: base64url do conteúdo
// "clienteId:perfil:expiraEm", ponto, base64url do HMAC-SHA256. A autenticação
// não é a falha plantada deste serviço; as duas versões exigem o mesmo token.

import { createHmac, timingSafeEqual } from "node:crypto";

export interface Sessao {
  clienteId: number;
  perfil: string;
}

export function lerToken(cabecalho: string | undefined, segredo: Buffer, agora = Date.now()): Sessao | null {
  if (!cabecalho?.startsWith("Bearer ")) return null;
  const partes = cabecalho.slice("Bearer ".length).split(".");
  const [conteudo, assinatura] = partes;
  if (partes.length !== 2 || !conteudo || !assinatura) return null;

  const esperada = createHmac("sha256", segredo).update(conteudo).digest();
  const recebida = Buffer.from(assinatura, "base64url");
  if (recebida.length !== esperada.length || !timingSafeEqual(recebida, esperada)) return null;

  const [cliente, perfil, expira] = Buffer.from(conteudo, "base64url").toString("utf8").split(":");
  const clienteId = Number(cliente);
  if (!Number.isSafeInteger(clienteId) || !perfil || Number(expira) * 1000 <= agora) return null;
  return { clienteId, perfil };
}
