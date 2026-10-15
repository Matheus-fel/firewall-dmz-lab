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

echo "[rules] === Passo 4: anti-spoofing na rede cliente ==="
# Um pacote que entra pela interface da LAN só é legítimo se o IP de
# origem pertencer à sub-rede da LAN. Caso contrário, alguém está forjando
# (spoofing) o endereço de outra zona para tentar enganar as regras.
# "-I <cadeia> 1" insere a regra na PRIMEIRA posição, antes de todas as outras.
rule -I INPUT   1 -i "$LAN_IF" ! -s "$LAN_SUBNET" -m comment --comment "S1 anti-spoofing LAN" -j DROP
rule -I FORWARD 1 -i "$LAN_IF" ! -s "$LAN_SUBNET" -m comment --comment "S1 anti-spoofing LAN" -j DROP

echo "[rules] === Passo 5: cadeia LOG_DROP (registra e descarta) ==="
# Cadeia própria para centralizar o descarte: primeiro registra no log do
# kernel (limitado a 5 por minuto para não encher o disco em um ataque) e
# depois descarta. Em alguns ambientes de container o kernel não permite
# LOG fora do namespace principal; nesse caso só avisamos e seguimos, pois
# o DROP continua funcionando (o log é um "extra", não a proteção).
rule -N LOG_DROP
if ! "$IPT" -A LOG_DROP -m limit --limit 5/min --limit-burst 10 \
        -j LOG --log-prefix "FW-DROP: " --log-level 4 2>/dev/null; then
    echo "[rules] aviso: alvo LOG indisponível; os pacotes serão apenas descartados"
fi
rule -A LOG_DROP -j DROP

echo "[rules] === Passo 6: regras do próprio firewall (cadeia INPUT) ==="
# I1: permite "ping" no gateway vindo da LAN (diagnóstico), com limite de
#     taxa para evitar inundação de ICMP. Todo o resto é descartado: o
#     firewall não oferece nenhum serviço (SSH, HTTP...) a ninguém.
rule -A INPUT -i "$LAN_IF" -p icmp --icmp-type echo-request \
     -m limit --limit 10/second --limit-burst 20 \
     -m comment --comment "I1 ping no gateway" -j ACCEPT
rule -A INPUT -m comment --comment "I2 negar o resto" -j LOG_DROP

echo "[rules] === Passo 7: matriz de regras entre zonas (cadeia FORWARD) ==="
# As regras abaixo correspondem 1:1 à tabela da seção 3 do relatório
# (docs/RELATORIO.md). Cada regra tem um rótulo (R1, R2...) no "comment".
# "--ctstate NEW" libera apenas o INÍCIO da conexão; as respostas já foram
# liberadas pela regra ESTABLISHED,RELATED do Passo 3.

# --- Liberações explícitas (ACCEPT) ----------------------------------
# R1: Rede cliente -> Web na DMZ, HTTP (TCP 80)
rule -A FORWARD -i "$LAN_IF" -o "$DMZ_IF" -s "$LAN_SUBNET" -d "$WEB_IP" \
     -p tcp --dport 80 -m conntrack --ctstate NEW \
     -m comment --comment "R1 LAN->WEB http" -j ACCEPT

# R2: Rede cliente -> Web na DMZ, HTTPS (TCP 443)
rule -A FORWARD -i "$LAN_IF" -o "$DMZ_IF" -s "$LAN_SUBNET" -d "$WEB_IP" \
     -p tcp --dport 443 -m conntrack --ctstate NEW \
     -m comment --comment "R2 LAN->WEB https" -j ACCEPT

# R3: Rede cliente -> Web, ICMP echo-request (ping de diagnóstico), com limite de taxa
rule -A FORWARD -i "$LAN_IF" -o "$DMZ_IF" -s "$LAN_SUBNET" -d "$WEB_IP" \
     -p icmp --icmp-type echo-request \
     -m limit --limit 10/second --limit-burst 20 \
     -m comment --comment "R3 LAN->WEB ping" -j ACCEPT

# --- Bloqueios explícitos (DROP com registro) ------------------------
# Seriam descartados de qualquer forma pela política padrão, mas escrevê-los
# deixa a intenção documentada e gera contadores (iptables -L -v) que servem
# de evidência nos testes.

# R4: Rede cliente -> Banco de dados, PostgreSQL (TCP 5432): PROIBIDO.
rule -A FORWARD -i "$LAN_IF" -o "$DB_IF" -s "$LAN_SUBNET" -d "$DB_IP" \
     -p tcp --dport 5432 \
     -m comment --comment "R4 LAN->DB postgres (DROP)" -j LOG_DROP

# R5: Rede cliente -> qualquer outra coisa no segmento do banco: PROIBIDO.
rule -A FORWARD -i "$LAN_IF" -o "$DB_IF" -s "$LAN_SUBNET" \
     -m comment --comment "R5 LAN->DB demais (DROP)" -j LOG_DROP

# R6: Rede cliente -> demais portas/protocolos do Web (22, 8080, 3306...): PROIBIDO.
rule -A FORWARD -i "$LAN_IF" -o "$DMZ_IF" -s "$LAN_SUBNET" \
     -m comment --comment "R6 LAN->WEB demais (DROP)" -j LOG_DROP

# R7: DMZ -> Rede cliente: o servidor web nunca INICIA conexões para a LAN
#     (só responde às que a LAN abriu, via ESTABLISHED). Contém um servidor
#     web comprometido.
rule -A FORWARD -i "$DMZ_IF" -o "$LAN_IF" \
     -m comment --comment "R7 DMZ->LAN (DROP)" -j LOG_DROP

# R8: Segmento do banco -> qualquer destino: o banco não inicia conexões.
rule -A FORWARD -i "$DB_IF" \
     -m comment --comment "R8 DB->qualquer (DROP)" -j LOG_DROP

# R9: DMZ <-> banco passando pelo firewall: não é permitido. O web fala
#     com o banco DIRETAMENTE no segmento db_net (onde os dois estão),
#     portanto esse tráfego nem chega ao firewall.
rule -A FORWARD -i "$DMZ_IF" -o "$DB_IF" \
     -m comment --comment "R9 DMZ->DB via firewall (DROP)" -j LOG_DROP

# R10: regra final (catch-all). Equivale à política DROP, mas registra o log.
rule -A FORWARD -m comment --comment "R10 negar o resto" -j LOG_DROP

echo "[rules] === Passo 8: NAT apenas LAN -> DMZ ==="
# MASQUERADE troca o IP de origem (cliente) pelo IP do firewall na DMZ.
# Vantagem: o servidor web responde diretamente ao firewall, que está no
# mesmo segmento, sem precisar de rota de retorno para a LAN. Assim os
# servidores NÃO precisam da capability NET_ADMIN (menor privilégio).
# O filtro (FORWARD) acontece ANTES do NAT, então as regras acima
# enxergam o IP real do cliente.
rule -t nat -A POSTROUTING -s "$LAN_SUBNET" -o "$DMZ_IF" \
     -m comment --comment "N1 NAT LAN->DMZ" -j MASQUERADE

echo "[rules] === Resumo final ==="
echo "[rules] Políticas:"
"$IPT" -S | grep '^-P'
echo "[rules] Cadeia FORWARD:"
"$IPT" -L FORWARD -n -v --line-numbers
