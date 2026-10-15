#!/bin/sh
# =====================================================================
# firewall/entrypoint.sh
#
# Roda toda vez que o container do firewall inicia. Passos:
#   1. Espera o Docker conectar o container às três redes.
#   2. Descobre qual interface (eth0, eth1, eth2...) pertence a cada rede.
#      O Docker NÃO garante a ordem dos nomes, então procuramos pelo IP.
#   3. Confere se o encaminhamento de pacotes (ip_forward) está ativo.
#   4. Escolhe o backend do iptables que funciona neste kernel.
#   5. Carrega as regras (rules.sh) e sinaliza que está pronto.
#
# Se qualquer passo falhar, o script ABORTA (set -e). É um comportamento
# proposital: um firewall que sobe sem regras seria pior que nenhum
# firewall ("fail closed").
# =====================================================================
set -eu

# ---------------------------------------------------------------------
# Parâmetros do ambiente (vêm do docker-compose.yml; valores padrão abaixo
# servem apenas como segurança caso alguma variável não seja informada).
# ---------------------------------------------------------------------
export FW_LAN_IP="${FW_LAN_IP:-172.20.0.254}"   # IP do firewall na rede cliente
export FW_DMZ_IP="${FW_DMZ_IP:-172.21.0.254}"   # IP do firewall na DMZ
export FW_DB_IP="${FW_DB_IP:-172.22.0.254}"     # IP do firewall no segmento de dados

export LAN_SUBNET="${LAN_SUBNET:-172.20.0.0/24}"
export DMZ_SUBNET="${DMZ_SUBNET:-172.21.0.0/24}"
export DB_SUBNET="${DB_SUBNET:-172.22.0.0/24}"

export WEB_IP="${WEB_IP:-172.21.0.10}"          # servidor web (na DMZ)
export DB_IP="${DB_IP:-172.22.0.20}"            # servidor de banco de dados

READY_FILE="/tmp/firewall-ready"                # usado pelo healthcheck do compose
rm -f "${READY_FILE}"                           # em um restart, começa "não pronto"

# ---------------------------------------------------------------------
# Função: devolve o nome da interface que possui o IP informado.
# "ip -o -4 addr show" imprime uma linha por endereço, por exemplo:
#   7: eth1    inet 172.21.0.254/24 brd ... scope global eth1
# O campo 2 é o nome da interface; o campo 4 é "IP/prefixo".
# ---------------------------------------------------------------------
iface_by_ip() {
    ip -o -4 addr show | awk -v wanted="$1" '{
        split($4, addr, "/")
        if (addr[1] == wanted) { print $2; exit }
    }'
}

# ---------------------------------------------------------------------
# 1 e 2) Espera (até 30 s) as três interfaces aparecerem e descobre os nomes.
# ---------------------------------------------------------------------
echo "[firewall] Procurando interfaces de rede..."
tries=0
while :; do
    LAN_IF="$(iface_by_ip "${FW_LAN_IP}")"
    DMZ_IF="$(iface_by_ip "${FW_DMZ_IP}")"
    DB_IF="$(iface_by_ip "${FW_DB_IP}")"

    # Achou as três? Então pode seguir.
    if [ -n "${LAN_IF}" ] && [ -n "${DMZ_IF}" ] && [ -n "${DB_IF}" ]; then
        break
    fi

    tries=$((tries + 1))
    if [ "${tries}" -ge 30 ]; then
        echo "[firewall] ERRO: não encontrei as 3 interfaces em 30 s." >&2
        echo "[firewall]   LAN='${LAN_IF}' DMZ='${DMZ_IF}' DB='${DB_IF}'" >&2
        exit 1
    fi
    sleep 1
done
export LAN_IF DMZ_IF DB_IF
echo "[firewall]   LAN (${FW_LAN_IP}) -> ${LAN_IF}"
echo "[firewall]   DMZ (${FW_DMZ_IP}) -> ${DMZ_IF}"
echo "[firewall]   DB  (${FW_DB_IP}) -> ${DB_IF}"

# ---------------------------------------------------------------------
# 3) Encaminhamento de pacotes (roteamento).
# O compose já define "net.ipv4.ip_forward=1" via "sysctls". Aqui apenas
# CONFERIMOS; se estiver desligado, tentamos ligar; se não der, abortamos.
# ---------------------------------------------------------------------
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "[firewall] ip_forward desligado, tentando ativar..."
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
fi
if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
    echo "[firewall] ERRO: não foi possível ativar net.ipv4.ip_forward." >&2
    exit 1
fi
echo "[firewall] net.ipv4.ip_forward = 1 (roteamento ativo)"

# ---------------------------------------------------------------------
# 4) Escolha do backend do iptables.
# Kernels modernos usam nf_tables ("iptables" padrão do Alpine); alguns
# hosts só têm o backend antigo ("iptables-legacy"). Usamos o primeiro
# que conseguir listar as regras sem erro.
# ---------------------------------------------------------------------
IPT=""
for candidate in iptables iptables-legacy iptables-nft; do
    if command -v "${candidate}" >/dev/null 2>&1 && "${candidate}" -L -n >/dev/null 2>&1; then
        IPT="${candidate}"
        break
    fi
done
if [ -z "${IPT}" ]; then
    echo "[firewall] ERRO: nenhum backend do iptables funciona (falta NET_ADMIN?)." >&2
    exit 1
fi
# O comando do IPv6 tem o mesmo sufixo (iptables-legacy -> ip6tables-legacy).
IPT6="ip6${IPT}"
export IPT IPT6
echo "[firewall] Backend do iptables: ${IPT} ($(${IPT} --version))"

# ---------------------------------------------------------------------
# 5) Carrega as regras e marca o firewall como pronto.
# ---------------------------------------------------------------------
echo "[firewall] Carregando regras..."
/usr/local/bin/rules.sh

touch "${READY_FILE}"
echo "[firewall] PRONTO: regras ativas."

# Entrega o controle ao comando do container (sleep infinity).
exec "$@"
