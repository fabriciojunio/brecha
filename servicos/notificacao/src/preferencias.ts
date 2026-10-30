// Preferências de notificação do cliente: canal e horário de silêncio.

export type Objeto = Record<string, unknown>;

function ehObjeto(valor: unknown): valor is Objeto {
  return typeof valor === "object" && valor !== null && !Array.isArray(valor);
}

// BRECHA-016: mesclagem recursiva que aceita qualquer chave. A chave
// "__proto__" que o JSON.parse cria vira, na atribuição, o protótipo de todo
// objeto do processo: {"__proto__":{"admin":true}} faz qualquer usuário sem a
// propriedade "admin" passar a ter admin = true.
export function mesclarV1(destino: Objeto, origem: Objeto): Objeto {
  for (const chave of Object.keys(origem)) {
    const valor = origem[chave];
    if (ehObjeto(valor)) {
      if (!ehObjeto(destino[chave])) destino[chave] = {};
      mesclarV1(destino[chave] as Objeto, valor);
    } else {
      destino[chave] = valor;
    }
  }
  return destino;
}

export interface Preferencias {
  canal: "email" | "sms" | "push";
  silencioInicio: number;
  silencioFim: number;
}

const CANAIS = new Set(["email", "sms", "push"]);

// v2: só os campos conhecidos, cada um validado; o resto é ignorado. Nada é
// copiado por chave vinda do cliente.
export function validarV2(atual: Preferencias, entrada: unknown): Preferencias | null {
  if (!ehObjeto(entrada)) return null;
  const novo: Preferencias = { ...atual };
  if ("canal" in entrada) {
    if (typeof entrada.canal !== "string" || !CANAIS.has(entrada.canal)) return null;
    novo.canal = entrada.canal as Preferencias["canal"];
  }
  for (const campo of ["silencioInicio", "silencioFim"] as const) {
    if (campo in entrada) {
      const hora = entrada[campo];
      if (typeof hora !== "number" || !Number.isInteger(hora) || hora < 0 || hora > 23) return null;
      novo[campo] = hora;
    }
  }
  return novo;
}
