# brecha

*[Read this in English](README.en.md)*

API bancária vulnerável de propósito, com a versão corrigida ao lado e o relatório de teste de
intrusão completo. Laboratório local, com dados simulados.

**Relatório:** [docs/relatorio-pentest.md](docs/relatorio-pentest.md) · [English](docs/relatorio-pentest.en.md)

**Cadeia de ataque, passo a passo:** [docs/cadeia-de-ataque.md](docs/cadeia-de-ataque.md) · [English](docs/cadeia-de-ataque.en.md)

## O que tem aqui

| Rota | O que é |
|---|---|
| `/v1` | A API como chega a produção quando ninguém revisa: nove falhas da OWASP API Security Top 10 (2023) |
| `/v2` | A mesma API com cada falha corrigida |
| `/v0` | Uma versão antiga, sem autenticação, que ninguém desligou |

| ID | Falha | Severidade |
|---|---|---|
| BRECHA-001 | Conta de outro cliente lida e movimentada pelo id (BOLA) | Alta |
| BRECHA-002 | Token sem assinatura e login sem limite | Alta |
| BRECHA-003 | Hash de senha na resposta e atribuição em massa do perfil | Alta |
| BRECHA-004 | Extrato sem limite de período | Alta |
| BRECHA-005 | Rota de administração aberta a qualquer cliente (BFLA) | Alta |
| BRECHA-006 | Transferência com valor negativo e condição de corrida | Alta |
| BRECHA-007 | SSRF na importação de comprovante | Média |
| BRECHA-008 | Pilha de exceção na resposta de erro | Média |
| BRECHA-009 | API legada sem autenticação ainda no ar | Alta |

Cada falha tem um teste que a explora no `/v1` e outro que prova o bloqueio no `/v2`
(`src/test/java/br/com/brecha/ExploracaoTest.java`). Os testes são a prova de conceito e o reteste ao
mesmo tempo.

## Como rodar

Java 21 e Maven.

```bash
mvn test                                  # 26 testes: exploração no v1, bloqueio no v2
mvn -DskipTests package
java -jar target/brecha-1.0.0.jar         # sobe só em 127.0.0.1:8080
bash docs/evidencias/capturar.sh          # regera as evidências do relatório
```

Contas de teste (dados simulados):

| E-mail | Senha | Perfil |
|---|---|---|
| ana@exemplo.com.br | ana-senha-2026 | cliente, conta 100 |
| bruno@exemplo.com.br | bruno-senha-2026 | cliente, conta 200 |
| operacao@exemplo.com.br | operacao-senha-2026 | administrador |

## Decisões

- **Spring Boot 4.1 e Java 21**, sem banco de dados. As falhas são de autorização e de regra de
  negócio, e nenhuma depende de SQL; menos peça, menos coisa para explicar.
- **As duas versões no mesmo código**, lado a lado, em vez de duas branches: a diferença entre a
  falha e a correção fica visível num `diff` de arquivo.
- **A aplicação só escuta em 127.0.0.1.** É vulnerável de propósito e não deve ser exposta em rede.
- **O hash de senha usa PBKDF2 com 600 mil iterações**, o valor da OWASP, porque o vazamento do
  BRECHA-003 precisa mostrar um hash de verdade.
- **A análise estática não pega essas falhas.** O Semgrep, com 129 regras, não apontou nenhuma
  (apêndice C do relatório). É o motivo de existir teste com contexto.

## Estrutura

```
src/main/java/br/com/brecha/
  dominio/      banco em memória, clientes, contas, transferências, hash de senha
  seguranca/    token sem assinatura (v1) e token assinado (v2)
  api/v0/       API legada
  api/v1/       API vulnerável e o tratador de erro que vaza a pilha
  api/v2/       API corrigida, validação de destino externo e erro no padrão RFC 9457
docs/
  relatorio-pentest.md        relatório no formato OWASP WSTG
  cadeia-de-ataque.md         a cadeia do SSRF ao controle da rede, passo a passo
  evidencias/                 requisições e respostas reais de cada achado
```

## Aviso

Use só para estudo, na sua máquina. As técnicas descritas aqui só podem ser aplicadas em sistemas com
autorização por escrito do dono.

## Uso de IA

Este projeto foi estruturado com apoio de ferramentas de IA generativa. Modelagem, regras de
negócio, revisão do código e conclusões foram revisadas e validadas por Fabrício Júnio.
