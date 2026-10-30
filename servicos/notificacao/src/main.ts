import { readFileSync } from "node:fs";
import { criarServidor } from "./servidor.ts";

function segredo(): Buffer {
  // Arquivo de segredo quando existir; variável de ambiente só no laboratório.
  const arquivo = process.env.BRECHA_SEGREDO_ARQUIVO;
  const valor = arquivo ? readFileSync(arquivo, "utf8").trim() : (process.env.BRECHA_SEGREDO ?? "");
  if (Buffer.byteLength(valor) < 32) throw new Error("BRECHA_SEGREDO precisa de pelo menos 32 bytes");
  return Buffer.from(valor);
}

const parceiro = process.env.NOTIFICACAO_PARCEIRO_URL;
if (!parceiro) throw new Error("NOTIFICACAO_PARCEIRO_URL não definida");

// Vulnerável de propósito: por padrão, só nesta máquina.
const endereco = process.env.NOTIFICACAO_ENDERECO ?? "127.0.0.1";
const porta = Number(process.env.NOTIFICACAO_PORTA ?? 8070);

const servidor = criarServidor({ segredo: segredo(), parceiro });
servidor.requestTimeout = 10_000;
servidor.headersTimeout = 5_000;
servidor.listen(porta, endereco, () => {
  console.log(JSON.stringify({ nivel: "info", mensagem: "notificação no ar", endereco, porta }));
});
