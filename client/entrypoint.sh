#!/bin/sh
# =====================================================================
# client/entrypoint.sh
#
# O cliente fica na rede "lan_net". As redes da DMZ (172.21.0.0/24) e do
# segmento de dados (172.22.0.0/24) NÃO são diretamente alcançáveis: o
# único caminho até elas é passando pelo FIREWALL.
#
# Num escritório real, o DHCP entregaria o firewall como "gateway padrão".
# Aqui, como o Docker não faz isso, criamos as rotas estáticas manualmente.
#
# Variáveis (definidas no docker-compose.yml):
#   GATEWAY_IP     -> IP do firewall na rede cliente (ex.: 172.20.0.254)
#   ROUTED_SUBNETS -> sub-redes que devem ser alcançadas via firewall
# =====================================================================
set -eu

# Valores padrão caso o compose não defina as variáveis.
GATEWAY_IP="${GATEWAY_IP:-172.20.0.254}"
ROUTED_SUBNETS="${ROUTED_SUBNETS:-172.21.0.0/24 172.22.0.0/24}"

echo "[client] Configurando rotas via firewall (${GATEWAY_IP})..."

for subnet in ${ROUTED_SUBNETS}; do
    # "replace" é idempotente: não falha se a rota já existir
    # (acontece quando o container é reiniciado).
    ip route replace "${subnet}" via "${GATEWAY_IP}"
    echo "[client]   rota ${subnet} -> ${GATEWAY_IP}"
done

echo "[client] Tabela de rotas final:"
ip route

# "exec" substitui este shell pelo comando do container (sleep infinity),
# fazendo com que ele receba os sinais do Docker (stop, restart) corretamente.
exec "$@"
