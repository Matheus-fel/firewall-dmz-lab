#!/bin/sh
# =====================================================================
# firewall/rules.sh
#
# Regras do Netfilter (iptables) do firewall da CerradoShop.
#
# Este script é chamado pelo entrypoint.sh, que já define as variáveis:
#   IPT / IPT6                  -> comandos iptables / ip6tables
#   LAN_IF, DMZ_IF, DB_IF       -> interfaces de cada rede
#   LAN_SUBNET, DMZ_SUBNET, DB_SUBNET, WEB_IP, DB_IP
#
# Conceitos usados (resumo para a defesa):
#   - Tabela "filter": decide ACEITAR ou DESCARTAR pacotes.
#       INPUT   = pacotes destinados AO PRÓPRIO firewall
#       FORWARD = pacotes que ATRAVESSAM o firewall (o caso principal aqui)
#       OUTPUT  = pacotes gerados PELO firewall
#   - Política padrão DROP: tudo o que não for liberado é descartado.
#   - Firewall "stateful": o módulo conntrack acompanha as conexões, então
#     só precisamos liberar o início (NEW); as respostas passam por
#     ESTABLISHED/RELATED.
# =====================================================================
set -eu

# Mostra cada comando antes de executá-lo. Assim o "docker compose logs
# firewall" funciona como evidência das regras que foram aplicadas.
rule() {
    echo "[rules] $IPT $*"
    "$IPT" "$@"
}

echo "[rules] === Passo 1: limpando regras antigas ==="
# -F apaga as regras de cada cadeia; -X apaga cadeias criadas pelo usuário.
# Fazer isso torna o script idempotente (pode rodar várias vezes).
rule -F
rule -X
rule -t nat -F

echo "[rules] === Passo 2: política padrão DROP ==="
# Esta é a base do modelo "deny by default" (negar por padrão).
rule -P INPUT   DROP
rule -P FORWARD DROP
rule -P OUTPUT  DROP

# Mesma política para IPv6. Não usamos IPv6 neste laboratório, então
# nenhuma regra de liberação existe: tudo é descartado. Se o container
# não tiver IPv6, o comando falha e apenas avisamos.
for chain in INPUT FORWARD OUTPUT; do
    "$IPT6" -P "$chain" DROP 2>/dev/null || echo "[rules] aviso: IPv6 indisponível (${chain})"
done

echo "[rules] === Passo 3: regras básicas de estado ==="
# Loopback (comunicação do firewall consigo mesmo) precisa funcionar.
rule -A INPUT  -i lo -j ACCEPT
rule -A OUTPUT -o lo -j ACCEPT

# Pacotes INVALID (fora de sequência, malformados ou sem conexão conhecida)
# são descartados antes de qualquer outra análise.
rule -A INPUT   -m conntrack --ctstate INVALID -j DROP
rule -A FORWARD -m conntrack --ctstate INVALID -j DROP

# Respostas de conexões já autorizadas passam livremente.
rule -A INPUT   -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
rule -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
rule -A OUTPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "[rules] Estado atual das políticas:"
"$IPT" -S | grep '^-P'
