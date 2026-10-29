package br.com.brecha;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.assertj.core.api.Assertions.assertThat;

/** Reteste do BRECHA-009: com a propriedade desligada, a rota antiga some. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "brecha.legado.ativo=false")
@DisplayName("BRECHA-009: reteste com o legado desligado")
class LegadoDesligadoTest {

    @Value("${local.server.port}")
    int porta;

    @Test
    void rotaAntigaNaoExisteMais() throws Exception {
        HttpResponse<String> r = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + porta + "/v0/clientes")).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(r.statusCode()).isEqualTo(404);
        assertThat(r.body()).doesNotContain("52998224725");
    }
}
