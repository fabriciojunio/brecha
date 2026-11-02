# From an ordinary account to control of the internal network

*[Leia em português](cadeia-de-ataque.md)*

This text walks through, in order, how an ordinary Brecha Bank customer account
reaches control of the internal network, and how the fixed version cuts each
step. The formal report, with every finding, severity and retest, is in
[relatorio-pentest.en.md](relatorio-pentest.en.md). The focus here is the chain:
no single step is the disaster; the disaster is their sum. Everything below runs
in CI, in the "Network, pivot and fixed version" job, against the lab and against
the fixed version.

The starting point is a customer account like Ana's, with nothing special about
it.

## 1. The SSRF that sees the network (BRECHA-015)

The `/v1` receipt import fetches a URL the client sends, without validating the
destination. By swapping the URL for internal addresses, the response and the
timing of each attempt reveal what is on the other side: the internal panel on
8080, Postgres on 5432, the report and receipt services. The API becomes a port
scanner inside the network, driven from outside.

The same flaw reads the internal panel's `/config` route, which needs no
authentication in the lab and returns the environment variables, including the
secret that signs the `/v2` tokens.

## 2. The forged token the "fixed" version accepts (BRECHA-001)

`/v2` validates the token in constant time and checks the role on every route.
Even so, with the secret leaked in the previous step, an admin token can be signed
that `/v2` accepts, listing every client. The lesson is the one that takes longest
to sink in: strong authentication is worth nothing when its secret leaks through
another service. The perimeter is the secret, not the algorithm.

## 3. Command execution through deserialization (BRECHA-017)

The `/v1/agendamentos` route deserializes a Java object from the body. With a
crafted object, built from a class in the application itself that runs a command
when read, the API container starts running whatever the attacker sends. From here
it ships its own environment to the outside machine, downloads a tunnel (Chisel)
and opens a reverse SOCKS: the internal network gains an exit to the attacker.

## 4. Nmap through the tunnel and post-exploitation

With the tunnel open, the attacker runs Nmap from outside, crossing the API into
the internal network, and maps hosts that were never exposed: Postgres and the
panel. That same panel, now reached from inside, hands over the database password.
What began with a customer account ended with the database password and a stable
network path inward.

## 5. The WAF that does not help on the wrong port

The version with a WAF in front blocks the serialized Java object. But the API
stays published on its origin port, next to the WAF. Anyone who knows the origin
address, as happens when the real IP leaks behind a CDN, sends the same request
directly and gets through. A WAF is one more layer, not the only door; if the
origin is exposed, it only protects those who were already taking the right path.

## How the fixed version cuts the chain

The fix is not a single control; it is closing each door in the chain, so that
breaking one does not lead to the next.

| Attack step | What cuts it in the fixed version |
|---|---|
| SSRF sees the network | `/v2` validates the destination against an allowlist and refuses internal and cloud metadata addresses |
| `/config` leaks the secret | the panel requires a token and has no `/config`; the secret comes from a file, not an environment variable |
| forged token | the lab secret and the repository default are rejected; the real secret never leaves a file readable only by the service |
| deserialization runs a command | `/v2` does not deserialize Java; it accepts only the expected fields, by schema |
| reverse tunnel | the internal network is `internal: true`, with no exit outward; the attacker never receives the connection |
| Nmap through the API | the API has no published port: only the WAF reaches it |
| WAF bypassed via the origin | there is no exposed origin; and the serialized Java object is blocked by a custom rule loaded as an OWASP CRS plugin |

Every row in this table is a check that runs in CI and must pass for the merge to
land. The network proof closes with every attack step working in the lab and every
one blocked in the fixed version.
