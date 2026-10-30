// Consulta ao parceiro que diz de quem é uma chave Pix, para a notificação
// mostrar o nome do recebedor. O parceiro é um terceiro: a resposta dele é
// entrada não confiável, como qualquer outra.

export interface Titular {
  nome: string;
  banco: string;
}

// BRECHA-015 (API10:2023): segue redirecionamento para qualquer endereço, não
// limita tempo nem tamanho e devolve o que vier. Um parceiro comprometido
// redireciona para um serviço interno, e o conteúdo dele volta para o cliente.
export async function consultarV1(baseDoParceiro: string, chave: string): Promise<unknown> {
  const resposta = await fetch(`${baseDoParceiro}/chaves/${encodeURIComponent(chave)}`);
  return resposta.json();
}

const TEMPO_LIMITE_MS = 3_000;
const TAMANHO_MAXIMO = 4 * 1024;

export class ParceiroInvalido extends Error {}

// v2: sem seguir redirecionamento, com tempo e tamanho limitados, e só os
// campos esperados, cada um com tipo e tamanho conferidos.
export async function consultarV2(baseDoParceiro: string, chave: string): Promise<Titular> {
  if (!/^[\w.@+-]{1,77}$/.test(chave)) throw new ParceiroInvalido("chave inválida");
  let resposta: Response;
  try {
    resposta = await fetch(`${baseDoParceiro}/chaves/${encodeURIComponent(chave)}`, {
      redirect: "error",
      signal: AbortSignal.timeout(TEMPO_LIMITE_MS),
    });
  } catch (erro) {
    // Redirecionamento recusado, tempo esgotado ou rede fora: para quem pediu,
    // tudo é o parceiro indisponível. O motivo fica no log.
    throw new ParceiroInvalido(`falha ao consultar o parceiro: ${String(erro)}`);
  }
  if (!resposta.ok) throw new ParceiroInvalido(`parceiro respondeu ${resposta.status}`);
  if (!resposta.headers.get("content-type")?.startsWith("application/json")) {
    throw new ParceiroInvalido("resposta do parceiro não é JSON");
  }
  const texto = await lerComLimite(resposta, TAMANHO_MAXIMO);
  const dados: unknown = JSON.parse(texto);
  if (typeof dados !== "object" || dados === null) throw new ParceiroInvalido("formato inesperado");
  const { nome, banco } = dados as Record<string, unknown>;
  if (typeof nome !== "string" || typeof banco !== "string" || nome.length > 100 || banco.length > 60) {
    throw new ParceiroInvalido("formato inesperado");
  }
  return { nome, banco };
}

async function lerComLimite(resposta: Response, limite: number): Promise<string> {
  if (!resposta.body) return "";
  const pedacos: Uint8Array[] = [];
  let total = 0;
  for await (const pedaco of resposta.body) {
    total += pedaco.length;
    if (total > limite) throw new ParceiroInvalido("resposta do parceiro grande demais");
    pedacos.push(pedaco);
  }
  return Buffer.concat(pedacos).toString("utf8");
}
