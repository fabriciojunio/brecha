# brecha

*[Leia em português](README.md)*

A deliberately vulnerable banking API, with the fixed version alongside and a complete penetration
test report. Local lab, simulated data.

**Report:** [docs/relatorio-pentest.en.md](docs/relatorio-pentest.en.md) · [Português](docs/relatorio-pentest.md)

## What is here

| Route | What it is |
|---|---|
| `/v1` | The API as it reaches production when nobody reviews it: nine flaws from the OWASP API Security Top 10 (2023) |
| `/v2` | The same API with every flaw fixed |
| `/v0` | An old, unauthenticated version nobody shut down |

| ID | Flaw | Severity |
|---|---|---|
| BRECHA-001 | Another customer's account read and debited by id (BOLA) | High |
| BRECHA-002 | Unsigned token and unlimited login attempts | High |
| BRECHA-003 | Password hash in the response and role mass assignment | High |
| BRECHA-004 | Statement with no period limit | High |
| BRECHA-005 | Administration route open to any customer (BFLA) | High |
| BRECHA-006 | Transfer with negative amount and a race condition | High |
| BRECHA-007 | SSRF in receipt import | Medium |
| BRECHA-008 | Exception stack trace in the error response | Medium |
| BRECHA-009 | Unauthenticated legacy API still live | High |

Each flaw has a test that exploits it on `/v1` and another that proves it is blocked on `/v2`
(`src/test/java/br/com/brecha/ExploracaoTest.java`). The tests are the proof of concept and the
retest at once.

## Running it

Java 21 and Maven.

```bash
mvn test                                  # 26 tests: exploitation on v1, blocking on v2
mvn -DskipTests package
java -jar target/brecha-1.0.0.jar         # listens on 127.0.0.1:8080 only
bash docs/evidencias/capturar.sh          # regenerates the report evidence
```

Test accounts (simulated data):

| Email | Password | Role |
|---|---|---|
| ana@exemplo.com.br | ana-senha-2026 | customer, account 100 |
| bruno@exemplo.com.br | bruno-senha-2026 | customer, account 200 |
| operacao@exemplo.com.br | operacao-senha-2026 | administrator |

## Decisions

- **Spring Boot 4.1 and Java 21**, no database. The flaws are authorisation and business-logic ones,
  none depends on SQL; fewer parts, less to explain.
- **Both versions in the same code**, side by side, instead of two branches: the difference between
  the flaw and the fix shows up in a single file diff.
- **The application only listens on 127.0.0.1.** It is vulnerable on purpose and must not be exposed
  on a network.
- **Password hashing uses PBKDF2 with 600,000 iterations**, the OWASP value, because the BRECHA-003
  leak needs to show a real hash.
- **Static analysis does not catch these flaws.** Semgrep, with 129 rules, flagged none of them
  (appendix C of the report). That is why testing with context exists.

## Layout

```
src/main/java/br/com/brecha/
  dominio/      in-memory bank, customers, accounts, transfers, password hashing
  seguranca/    unsigned token (v1) and signed token (v2)
  api/v0/       legacy API
  api/v1/       vulnerable API and the error handler that leaks the stack trace
  api/v2/       fixed API, external destination validation and RFC 9457 errors
docs/
  relatorio-pentest.en.md     report in OWASP WSTG format
  evidencias/                 real requests and responses for each finding
```

## Notice

For study only, on your own machine. The techniques described here may only be used on systems with
written authorisation from the owner.
