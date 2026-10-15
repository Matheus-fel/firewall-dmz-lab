# Relatório Técnico — Firewall Linux, Arquitetura Netfilter & Iptables

**Instituição:** Instituto Federal Goiano — Campus Ceres
**Curso:** Bacharelado em Sistemas de Informação
**Disciplina:** Segurança da Informação
**Docente:** Prof. Roitier Campos Gonçalves
**Discente:** Matheus Felipe
**Modalidade:** Individual · **Valor:** 2,0 pontos · **Entrega:** 15/10/2026

---

## Sumário

1. [Definição do Case](#1-definição-do-case)
2. [Diagnóstico: Cenário Atual vs. Proposta de Solução](#2-diagnóstico-cenário-atual-vs-proposta-de-solução)
3. [Matriz de Regras de Segurança (Firewall)](#3-matriz-de-regras-de-segurança-firewall)
4. [Metodologia de Testes e Validação](#4-metodologia-de-testes-e-validação)

---

## 1. Definição do Case

### 1.1 Descrição da empresa

O estudo de caso é uma situação **hipotética baseada na realidade** de pequenas
empresas de comércio eletrônico do interior do Brasil.

A **CerradoShop** é uma loja virtual de produtos regionais (doces, cafés
especiais, artesanato) sediada em Ceres-GO. Ela tem cerca de 25 colaboradores,
divididos entre atendimento, financeiro, logística e administração. A empresa
cresceu rápido nos últimos dois anos: começou vendendo por redes sociais e hoje
recebe pedidos diretamente pelo próprio site.

A infraestrutura de TI foi montada de forma improvisada, conforme a necessidade
surgia, e hoje é mantida por uma única pessoa, sem uma política formal de
segurança.

### 1.2 Contexto do negócio

O site é a principal fonte de receita: um pedido que não entra por indisponibilidade
do site é uma venda perdida. Ao mesmo tempo, o banco de dados guarda **dados
pessoais de clientes** (nome, e-mail, endereço, histórico de compras), o que
traz obrigações da **LGPD (Lei nº 13.709/2018)** — em especial o dever de adotar
medidas técnicas para proteger esses dados contra acessos não autorizados
(art. 46).

Os pontos de negócio que guiam as decisões deste trabalho são:

- **Disponibilidade** do site para clientes e funcionários.
- **Confidencialidade** dos dados de clientes guardados no banco.
- **Controle de acesso** — cada tipo de usuário deve alcançar apenas o que
  precisa para trabalhar.

### 1.3 Serviços que precisam operar

| Serviço | Tecnologia | Quem acessa | Porta |
|---|---|---|---|
| Loja virtual / painel administrativo | Nginx (HTTP e HTTPS) | Funcionários (rede interna) e clientes | TCP 80 e 443 |
| Banco de dados de produtos e pedidos | PostgreSQL 16 | **Somente** o servidor web | TCP 5432 |
| Estações de trabalho dos funcionários | Alpine Linux (simulação) | Usam o site; não administram o banco | — |
| Gateway / firewall de borda | Linux + iptables | Infraestrutura (ninguém acessa serviços nele) | — |

> **Nota sobre a simulação:** o site seria exposto à internet em produção.
> Neste laboratório, o acesso do público externo é representado pela rede
> cliente (LAN), que é a origem de tráfego que o firewall precisa filtrar. A
> mesma lógica de regras vale para qualquer origem não confiável.
