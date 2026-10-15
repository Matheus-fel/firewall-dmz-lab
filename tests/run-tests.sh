#!/usr/bin/env bash
# =====================================================================
# tests/run-tests.sh
#
# Bateria de testes automatizados do firewall (positivos e negativos).
# Deve ser executada NA MÁQUINA HOSPEDEIRA, na raiz do repositório, depois
# de "docker compose up -d --build":
#
#     ./tests/run-tests.sh
#
# Cada teste imprime PASS ou FAIL. Ao final o script devolve:
#     exit 0 -> todos os testes passaram
#     exit 1 -> pelo menos um teste falhou
#
# Os comandos são executados DENTRO dos containers com "docker compose exec",
# portanto o tráfego realmente passa pelo firewall.
# =====================================================================
set -u

# Garante que o script funcione mesmo se chamado de outra pasta.
cd "$(dirname "$0")/.." || exit 1

# Carrega o .env (se existir) para usar as mesmas senhas do compose.
if [ -f .env ]; then
    set -a
    # shellcheck disable=SC1091
    . ./.env
    set +a
fi
POSTGRES_DB="${POSTGRES_DB:-lojadb}"
APP_DB_PASSWORD="${APP_DB_PASSWORD:-App-Lab-2026}"

# ---------------------------------------------------------------------
# Cores (só quando a saída é um terminal) e contadores
# ---------------------------------------------------------------------
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; BOLD=""; RESET=""
fi
PASSED=0
FAILED=0

pass() { PASSED=$((PASSED + 1)); echo "  ${GREEN}PASS${RESET}  $1"; }
fail() {
    FAILED=$((FAILED + 1))
    echo "  ${RED}FAIL${RESET}  $1"
    # Mostra a saída do comando (indentada) para ajudar no diagnóstico.
    [ -n "${2:-}" ] && echo "$2" | sed 's/^/        | /'
}
section() { echo; echo "${BOLD}== $1 ==${RESET}"; }

# Atalho: executa um comando dentro de um serviço do compose.
#   dx client curl ...   ==   docker compose exec -T client curl ...
dx() { docker compose exec -T "$@"; }

# Espera sucesso (exit 0): usado nos TESTES POSITIVOS.
#   expect_success "descrição" comando args...
expect_success() {
    local desc="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then pass "$desc"; else fail "$desc" "$out"; fi
}

# Espera FALHA (exit != 0): usado nos TESTES NEGATIVOS (bloqueios).
expect_failure() {
    local desc="$1"; shift
    local out
    if out="$("$@" 2>&1)"; then
        fail "$desc (deveria ter sido BLOQUEADO)" "$out"
    else
        pass "$desc"
    fi
}

# Compara o valor obtido com o esperado.
#   expect_equal "descrição" "esperado" "obtido"
expect_equal() {
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1" "esperado='$2' obtido='$3'"; fi
}

# Lê o contador de pacotes de uma regra da cadeia FORWARD, procurando
# pelo rótulo (comment) da regra. "-x" mostra o número exato (sem K/M).
fw_packets() {
    dx firewall iptables -L FORWARD -n -v -x 2>/dev/null \
        | awk -v tag="$1" 'index($0, tag) { print $1; exit }'
}

# =====================================================================
echo "${BOLD}Testes do firewall CerradoShop${RESET}"

# ---------------------------------------------------------------------
section "0. Pré-requisitos: ambiente no ar"
# ---------------------------------------------------------------------
# Aguarda até 60 s o servidor web responder (ele sobe depois do banco).
ready=0
for _ in $(seq 1 30); do
    if dx web wget -q -O /dev/null http://127.0.0.1/health 2>/dev/null; then ready=1; break; fi
    sleep 2
done
if [ "$ready" -eq 1 ]; then
    pass "serviço web respondendo localmente"
else
    fail "serviço web não ficou pronto em 60 s (rode: docker compose up -d --build)"
    echo; echo "Abortando: ambiente não está pronto."; exit 1
fi

expect_success "firewall carregou as regras (arquivo /tmp/firewall-ready)" \
    dx firewall test -f /tmp/firewall-ready

expect_equal "roteamento ativo no firewall (ip_forward = 1)" "1" \
    "$(dx firewall cat /proc/sys/net/ipv4/ip_forward 2>/dev/null | tr -d '\r')"

policies="$(dx firewall iptables -S 2>/dev/null | grep -c '^-P \(INPUT\|FORWARD\|OUTPUT\) DROP')"
expect_equal "políticas INPUT, FORWARD e OUTPUT em DROP" "3" "$policies"

# ---------------------------------------------------------------------
section "1. Testes POSITIVOS (o que DEVE funcionar)"
# ---------------------------------------------------------------------
http_code="$(dx client curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://dmz-web 2>/dev/null)"
expect_equal "P1  cliente -> web HTTP  (curl http://dmz-web) retorna 200" "200" "$http_code"

https_code="$(dx client curl -sk -o /dev/null -w '%{http_code}' --max-time 5 https://dmz-web 2>/dev/null)"
expect_equal "P2  cliente -> web HTTPS (curl -k https://dmz-web) retorna 200" "200" "$https_code"

expect_success "P3  cliente -> web ICMP (ping dmz-web)" \
    dx client ping -c 2 -W 2 dmz-web

expect_success "P4  cliente -> gateway ICMP (ping no firewall 10.77.1.254)" \
    dx client ping -c 2 -W 2 10.77.1.254

expect_success "P5  web -> banco, porta TCP 5432 aberta (mesmo segmento db_net)" \
    dx web nc -z -w 3 db 5432

rows="$(dx -e PGPASSWORD="$APP_DB_PASSWORD" web psql -h db -U loja_app -d "$POSTGRES_DB" -tAc 'SELECT count(*) FROM produtos' 2>/dev/null | tr -d '\r')"
expect_equal "P6  web -> banco autenticado (loja_app lê 3 produtos)" "3" "$rows"

# ---------------------------------------------------------------------
section "2. Testes NEGATIVOS (o que DEVE ser bloqueado)"
# ---------------------------------------------------------------------
expect_failure "N1  cliente -> banco TCP 5432 (nc dmz-db 5432)" \
    dx client nc -z -w 3 dmz-db 5432

# Tentativa real de login: o esperado é estourar o tempo de conexão
# (pacote descartado em silêncio), e não receber "connection refused".
psql_out="$(dx client psql "host=dmz-db port=5432 user=loja_app dbname=$POSTGRES_DB connect_timeout=4" -c 'SELECT 1' 2>&1)"
if echo "$psql_out" | grep -qi 'timeout'; then
    pass "N2  cliente -> banco via psql: tempo esgotado (pacote descartado pelo DROP)"
else
    fail "N2  cliente -> banco via psql deveria dar timeout" "$psql_out"
fi

nmap_db="$(dx client nmap -Pn -n -p 5432 dmz-db 2>&1)"
if echo "$nmap_db" | grep -q 'filtered' && ! echo "$nmap_db" | grep -q ' open '; then
    pass "N3  nmap -Pn -p 5432 dmz-db: porta 'filtered' (firewall descarta)"
else
    fail "N3  nmap deveria mostrar 5432 como filtered" "$nmap_db"
fi

# Varre portas comuns do web: só 80 e 443 podem aparecer como "open".
open_ports="$(dx client nmap -Pn -n -p 22,80,443,3306,5432,8080 --open dmz-web 2>&1 | grep -cE '^[0-9]+/tcp +open')"
expect_equal "N4  nmap no web: somente 2 portas abertas (80 e 443)" "2" "$open_ports"

expect_failure "N5  cliente -> web porta 8080 (não liberada)" \
    dx client nc -z -w 3 dmz-web 8080

expect_failure "N6  cliente -> SSH no firewall (porta 22 do gateway)" \
    dx client nc -z -w 3 10.77.1.254 22

expect_failure "N7  cliente -> banco ICMP (ping dmz-db)" \
    dx client ping -c 1 -W 2 dmz-db

# O web também tem IP no segmento do banco. Tentar entrar por esse IP
# (10.77.3.10) é um "atalho" que o firewall precisa bloquear (regra R5).
expect_failure "N8  cliente -> web pelo IP do segmento do banco (10.77.3.10:80)" \
    dx client curl -s -o /dev/null --max-time 4 http://10.77.3.10

# Anti-spoofing: o cliente (que tem NET_ADMIN) cria um IP falso fora da LAN
# e tenta usá-lo como origem. O firewall deve descartar (regra S1).
# Conferimos o código de saída do curl: 28 = "tempo esgotado" (pacote
# descartado). Qualquer outro código (ex.: 45, falha ao usar o IP) indica
# que o teste não foi montado corretamente, e não que o firewall bloqueou.
spoof_rc="$(dx client sh -c '
    dev=$(ip -o -4 addr show | awk "\$4 ~ /^10\\.77\\.1\\.10\\// {print \$2; exit}")
    ip addr add 10.99.0.5/32 dev "$dev" || { echo 99; exit 0; }
    curl -s -o /dev/null --max-time 4 --interface 10.99.0.5 http://dmz-web
    rc=$?
    ip addr del 10.99.0.5/32 dev "$dev"
    echo $rc' 2>/dev/null | tail -n 1 | tr -d '\r')"
expect_equal "N9  anti-spoofing: pacote com IP de origem forjado expira (curl rc=28)" "28" "$spoof_rc"

# ---------------------------------------------------------------------
section "3. Evidência no firewall: contadores das regras"
# ---------------------------------------------------------------------
# Prova que o bloqueio foi feito PELA REGRA do firewall (e não por falta de
# rota): os contadores de pacotes das regras de DROP precisam ter aumentado.
r1="$(fw_packets 'R1 LAN->WEB http')"
r4="$(fw_packets 'R4 LAN->DB postgres')"
[ "${r1:-0}" -gt 0 ] && pass "R1 (ACCEPT http) contou ${r1} pacotes" || fail "R1 não contou pacotes"
[ "${r4:-0}" -gt 0 ] && pass "R4 (DROP LAN->DB 5432) contou ${r4} pacotes" || fail "R4 não contou pacotes"

echo
echo "Cadeia FORWARD (evidência para o relatório):"
dx firewall iptables -L FORWARD -n -v --line-numbers 2>/dev/null | sed 's/^/  /'

# ---------------------------------------------------------------------
echo
echo "${BOLD}Resumo:${RESET} ${GREEN}${PASSED} passaram${RESET}, ${RED}${FAILED} falharam${RESET}"
[ "$FAILED" -eq 0 ]
