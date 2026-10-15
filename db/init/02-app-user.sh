#!/bin/sh
# =====================================================================
# db/init/02-app-user.sh
#
# Cria o usuário usado PELA APLICAÇÃO (servidor web) com o MENOR
# PRIVILÉGIO possível: só lê/grava nas tabelas da loja. Não é superusuário
# e não pode criar nem apagar tabelas.
#
# O usuário administrador (POSTGRES_USER) só é aceito pelo socket local
# do container (ver pg_hba.conf), nunca pela rede.
#
# A senha vem da variável de ambiente APP_DB_PASSWORD (definida no
# docker-compose.yml / .env), para não ficar escrita dentro do código.
# =====================================================================

# Nota: o PostgreSQL executa este arquivo (ele recebe permissão de execução
# no repositório). Se for apenas "lido" (source) em algum ambiente, o
# comando abaixo também funciona.

# ":'app_pass'" faz o psql inserir a senha já entre aspas e escapada,
# evitando problemas de SQL injection mesmo em um script de laboratório.
psql -v ON_ERROR_STOP=1 \
     --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_pass="$APP_DB_PASSWORD" <<'EOSQL'

-- Usuário da aplicação: pode conectar (LOGIN), sem nenhum poder administrativo.
CREATE ROLE loja_app LOGIN PASSWORD :'app_pass'
    NOSUPERUSER NOCREATEDB NOCREATEROLE;

-- Permissões mínimas: apenas operações de dados (sem DDL).
GRANT SELECT, INSERT, UPDATE ON produtos, clientes, pedidos TO loja_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO loja_app;

EOSQL
