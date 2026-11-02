# Da conta comum ao controle da rede interna

*[Read this in English](cadeia-de-ataque.en.md)*

Este texto conta, em ordem, como uma conta comum de cliente do Banco Brecha chega
ao controle da rede interna, e como a versão corrigida corta cada passo. O
relatório formal, com cada achado, severidade e reteste, está em
[relatorio-pentest.md](relatorio-pentest.md). Aqui o foco é a cadeia: nenhum passo
sozinho é o desastre; o desastre é a soma deles. Tudo o que está abaixo roda na
CI, no job "Rede, pivô e versão corrigida", contra o laboratório e contra a
versão corrigida.

O ponto de partida é uma conta de cliente igual à da Ana, sem nada de especial.

## 1. O SSRF que enxerga a rede (BRECHA-015)

A importação de comprovante do `/v1` busca uma URL que o cliente manda, sem
validar o destino. Trocando a URL por endereços internos, a resposta e o tempo de
cada tentativa dizem o que existe do outro lado: o painel interno na 8080, o
Postgres na 5432, os serviços de relatório e de comprovante. A API vira um
scanner de portas de dentro da rede, operado de fora.

A mesma falha lê a rota `/config` do painel interno, que não pede autenticação no
laboratório e devolve as variáveis de ambiente, incluindo o segredo que assina os
tokens do `/v2`.

## 2. O token forjado que a versão "corrigida" aceita (BRECHA-001)

O `/v2` valida o token com tempo constante e checa o papel em cada rota. Mesmo
assim, de posse do segredo vazado no passo anterior, dá para assinar um token de
administrador que o `/v2` aceita, e listar todos os clientes. A lição é a que mais
custa a entrar: uma autenticação forte não vale nada quando o segredo dela vaza
por outro serviço. O perímetro é o segredo, não o algoritmo.

## 3. Execução de comando pela desserialização (BRECHA-017)

A rota `/v1/agendamentos` desserializa um objeto Java que vem no corpo. Com um
objeto próprio, construído a partir de uma classe da própria aplicação que executa
um comando ao ser lida, o contêiner da API passa a rodar o que o atacante mandar.
A partir daqui ele manda o próprio ambiente para a máquina de fora, baixa um túnel
(Chisel) e abre um SOCKS reverso: a rede interna ganha uma saída para o atacante.

## 4. Nmap pelo túnel e pós-exploração

Com o túnel aberto, o atacante roda o Nmap de fora atravessando a API, pela rede
interna, e mapeia os hosts que nunca estiveram expostos: o Postgres e o painel. O
mesmo painel, agora alcançado por dentro, entrega a senha do banco. O que começou
com uma conta de cliente terminou com a senha do banco e um caminho de rede
estável para dentro.

## 5. O WAF que não adianta pela porta errada

A versão com WAF na frente barra o objeto Java serializado. Só que a API continua
publicada na porta de origem, ao lado do WAF. Quem conhece o endereço de origem,
como acontece quando o IP real vaza atrás de um CDN, manda o mesmo pedido direto e
passa. WAF é uma camada a mais, não a única porta; se a origem fica exposta, ele
só protege quem já ia pelo caminho certo.

## Como a versão corrigida corta a cadeia

A correção não é um controle só; é fechar cada porta da cadeia, para que furar uma
não leve à seguinte.

| Passo do ataque | O que corta na versão corrigida |
|---|---|
| SSRF enxerga a rede | o `/v2` valida o destino por lista de permissões e recusa endereço interno e o de metadados da nuvem |
| `/config` entrega segredo | o painel exige token e não tem `/config`; segredo vem de arquivo, não de variável de ambiente |
| token forjado | o segredo do laboratório e o padrão do repositório são recusados; o segredo real nunca sai de arquivo legível só pelo serviço |
| desserialização executa comando | o `/v2` não desserializa Java; aceita só os campos esperados, por esquema |
| túnel reverso | a rede interna é `internal: true`, sem saída para fora; o atacante não recebe a conexão |
| Nmap pela API | a API não tem porta publicada: só o WAF chega nela |
| WAF contornado pela origem | não há origem exposta; e o objeto Java serializado é barrado por uma regra própria carregada como plugin do OWASP CRS |

Cada linha dessa tabela é uma verificação que roda na CI e precisa passar para o
merge entrar. A prova de rede fecha com todas as etapas do ataque funcionando no
laboratório e todas barradas na versão corrigida.
