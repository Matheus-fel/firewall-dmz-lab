# =====================================================================
# client/Dockerfile
# Estação de trabalho interna (rede cliente / LAN) da CerradoShop.
#
# É a máquina de onde o avaliador executa os testes positivos e negativos:
# curl (HTTP/HTTPS), nmap (varredura de portas), nc (teste de porta TCP)
# e psql (tentativa de acesso ao banco).
# =====================================================================

# Versão fixa da imagem base: garante que o ambiente seja reproduzível.
FROM alpine:3.20

# Ferramentas de rede usadas nos testes:
#   curl               -> requisições HTTP/HTTPS
#   nmap               -> varredura de portas (teste negativo ao banco)
#   netcat-openbsd     -> "nc -z" testa se uma porta TCP está aberta
#   iproute2           -> comando "ip", usado para criar as rotas estáticas
#   postgresql-client  -> "psql", para provar que o banco não é acessível
#   bind-tools         -> "dig/nslookup", para diagnóstico de nomes
RUN apk add --no-cache \
        curl \
        nmap \
        netcat-openbsd \
        iproute2 \
        postgresql-client \
        bind-tools

# O entrypoint cria as rotas para a DMZ e para o segmento de dados.
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

# Mantém o container vivo: os testes são executados com "docker compose exec".
CMD ["sleep", "infinity"]
