# =====================================================================
# firewall/Dockerfile
# Container FIREWALL: gateway/roteador entre LAN, DMZ e segmento de dados.
#
# Usa o Netfilter do kernel Linux, configurado pelo comando "iptables".
# As regras são carregadas automaticamente pelo entrypoint.sh quando o
# container sobe (nenhum passo manual).
# =====================================================================

FROM alpine:3.20

# iptables        -> interface de linha de comando do Netfilter
# ip6tables       -> mesma política DROP aplicada ao IPv6 (nada deve vazar por ele)
# iproute2        -> comando "ip", usado para descobrir as interfaces de rede
# conntrack-tools -> "conntrack -L" mostra as conexões rastreadas (útil na defesa/demonstração)
RUN apk add --no-cache iptables ip6tables iproute2 conntrack-tools \
    # Alguns hosts só têm o backend "legacy" do iptables no kernel.
    # Instalamos o pacote opcional para o entrypoint poder usar o que funcionar.
    && (apk add --no-cache iptables-legacy || echo "aviso: iptables-legacy indisponível, usando só nft")

# Scripts do firewall:
#   entrypoint.sh -> prepara o ambiente (descobre interfaces, ativa o roteamento)
#   rules.sh      -> contém as regras do iptables (matriz de segurança)
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY rules.sh      /usr/local/bin/rules.sh
RUN chmod +x /usr/local/bin/entrypoint.sh /usr/local/bin/rules.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Mantém o container vivo depois que as regras foram carregadas.
CMD ["sleep", "infinity"]
