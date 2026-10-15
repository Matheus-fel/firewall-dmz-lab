-- =====================================================================
-- db/init/01-schema.sql
--
-- Executado automaticamente pelo PostgreSQL SOMENTE na primeira criação
-- do volume de dados (arquivos em /docker-entrypoint-initdb.d, em ordem
-- alfabética). Cria as tabelas da loja e alguns dados fictícios.
-- =====================================================================

-- Produtos vendidos no site.
CREATE TABLE produtos (
    id      SERIAL PRIMARY KEY,
    nome    VARCHAR(100)  NOT NULL,
    preco   NUMERIC(10,2) NOT NULL CHECK (preco >= 0),
    estoque INTEGER       NOT NULL DEFAULT 0
);

-- Clientes: contém DADOS PESSOAIS (protegidos pela LGPD). É justamente por
-- isso que este banco fica isolado e inacessível para a rede cliente.
CREATE TABLE clientes (
    id     SERIAL PRIMARY KEY,
    nome   VARCHAR(120) NOT NULL,
    email  VARCHAR(120) NOT NULL UNIQUE,
    cidade VARCHAR(80)
);

-- Pedidos feitos pelos clientes.
CREATE TABLE pedidos (
    id         SERIAL PRIMARY KEY,
    cliente_id INTEGER       NOT NULL REFERENCES clientes(id),
    produto_id INTEGER       NOT NULL REFERENCES produtos(id),
    quantidade INTEGER       NOT NULL CHECK (quantidade > 0),
    criado_em  TIMESTAMP     NOT NULL DEFAULT now()
);

-- Dados fictícios (nenhuma pessoa real).
INSERT INTO produtos (nome, preco, estoque) VALUES
    ('Doce de leite artesanal', 18.90, 120),
    ('Café especial 250g',      32.50,  80),
    ('Cesta de pequi',          45.00,  25);

INSERT INTO clientes (nome, email, cidade) VALUES
    ('Cliente Exemplo 1', 'cliente1@example.com', 'Ceres'),
    ('Cliente Exemplo 2', 'cliente2@example.com', 'Goiânia');

INSERT INTO pedidos (cliente_id, produto_id, quantidade) VALUES
    (1, 1, 2),
    (2, 2, 1);
