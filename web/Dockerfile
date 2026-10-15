# =====================================================================
# web/Dockerfile
# Servidor web da DMZ (loja virtual da CerradoShop).
#
# Baseado no Nginx oficial. Acrescentamos apenas:
#   - openssl            -> gerar o certificado HTTPS autoassinado
#   - netcat-openbsd     -> "nc -z" para testar conectividade com o banco
#   - postgresql-client  -> "psql", usado no teste web -> banco (positivo)
#
# A configuração do Nginx (nginx.conf) e o site (html/) NÃO ficam dentro
# da imagem: são montados como volumes pelo docker-compose.yml. Assim é
# possível editar o site sem reconstruir a imagem.
# =====================================================================

# Versão fixa (reprodutibilidade).
FROM nginx:1.27-alpine

RUN apk add --no-cache openssl netcat-openbsd postgresql-client

# Gera, durante o build, um certificado autoassinado válido por 1 ano.
# É suficiente para o laboratório (por isso o curl precisa do -k).
# Em produção, seria usado um certificado emitido por uma CA (ex.: Let's Encrypt).
RUN mkdir -p /etc/nginx/certs \
    && openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -subj "/C=BR/ST=GO/L=Ceres/O=CerradoShop/CN=dmz-web" \
        -addext "subjectAltName=DNS:dmz-web,DNS:web" \
        -keyout /etc/nginx/certs/server.key \
        -out    /etc/nginx/certs/server.crt \
    && chmod 600 /etc/nginx/certs/server.key
