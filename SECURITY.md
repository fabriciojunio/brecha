# Segurança

*[Read this in English](SECURITY.en.md)*

Este repositório é vulnerável de propósito. As 19 falhas do [relatório](docs/relatorio-pentest.md)
(BRECHA-001 a BRECHA-019) estão aqui para serem exploradas, cada uma com prova de conceito, correção e
reteste no relatório. Elas **não** são achado para reportar.

## O que vale reportar

- Falha na **versão corrigida** (`/v2` e os serviços na forma corrigida) que o relatório dá como
  fechada: um reteste que passa quando não devia, ou uma variante que a correção não cobre.
- Algo que faça o laboratório sair da máquina de quem roda: porta escutando fora de `127.0.0.1`,
  imagem ou script que exponha serviço em rede.
- Segredo real no código ou no histórico. Os valores do laboratório são fictícios; uma credencial de serviço de verdade não deveria estar aqui.
- Falha na esteira (`.github/workflows/`) ou nas evidências que faça a CI provar menos do que diz.

## Como avisar

Escreva para **fabricioad444@gmail.com** com o que encontrou e como reproduzir. É um projeto de
portfólio mantido por uma pessoa: a resposta depende de disponibilidade.

## Como rodar com segurança

Toda porta publicada escuta só em `127.0.0.1`, e a aplicação Java também. Não mude isso, não suba
o laboratório em servidor nem em rede compartilhada, e não use dado real. As técnicas descritas aqui
só podem ser aplicadas em sistema com autorização por escrito do dono.
