package br.com.brecha;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * BRECHA-019: transferências em série sem limite no /v1, e o limite por
 * cliente, por dispositivo e por ritmo no /v2.
 *
 * <p>Limites pequenos só neste contexto (6 por cliente, 8 por dispositivo,
 * rajada de 4 em 2 segundos), para o teste não esperar minutos.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "brecha.limite.transferencias-por-minuto=6",
        "brecha.limite.transferencias-por-dispositivo=8",
        "brecha.limite.rajada=4"})
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("BRECHA-019: automação e abuso nas transferências")
class AbusoTest {

    private static final Pattern TOKEN = Pattern.compile("\"token\"\\s*:\\s*\"([^\"]+)\"");

    @Value("${local.server.port}")
    int porta;

    private final HttpClient http = HttpClient.newHttpClient();

    String entrar(String versao, String email, String senha) throws Exception {
        String corpo = "{\"email\":\"" + email + "\",\"senha\":\"" + senha + "\"}";
        Matcher m = TOKEN.matcher(enviar("/" + versao + "/sessoes", null, null, corpo).body());
        assertThat(m.find()).isTrue();
        return m.group(1);
    }

    HttpResponse<String> enviar(String caminho, String token, String dispositivo, String corpo) throws Exception {
        var pedido = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + porta + caminho))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(corpo));
        if (token != null) {
            pedido.header("Authorization", "Bearer " + token);
        }
        if (dispositivo != null) {
            pedido.header("X-Dispositivo", dispositivo);
        }
        return http.send(pedido.build(), HttpResponse.BodyHandlers.ofString());
    }

    int transferirV2(String token, String dispositivo) throws Exception {
        return enviar("/v2/transferencias", token, dispositivo, "{\"destino\":300,\"valor\":1}").statusCode();
    }

    @Test
    void v1AceitaVinteTransferenciasSeguidas() throws Exception {
        String bruno = entrar("v1", "bruno@exemplo.com.br", "bruno-senha-2026");
        for (int i = 0; i < 20; i++) {
            assertThat(enviar("/v1/transferencias", bruno, null, "{\"origem\":200,\"destino\":300,\"valor\":1}").statusCode())
                    .isEqualTo(200);
        }
    }

    @Test
    void v2BloqueiaORitmoDeRoboPorUmMinuto() throws Exception {
        String bruno = entrar("v2", "bruno@exemplo.com.br", "bruno-senha-2026");
        List<Integer> status = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            status.add(transferirV2(bruno, null));
        }
        assertThat(status).containsExactly(200, 200, 200, 429);

        HttpResponse<String> depois = enviar("/v2/transferencias", bruno, null, "{\"destino\":300,\"valor\":1}");
        assertThat(depois.statusCode()).isEqualTo(429);
        assertThat(Long.parseLong(depois.headers().firstValue("Retry-After").orElseThrow())).isBetween(50L, 60L);
    }

    @Test
    void v2LimitaPorClienteNoMinuto() throws Exception {
        String bruno = entrar("v2", "bruno@exemplo.com.br", "bruno-senha-2026");
        List<Integer> status = new ArrayList<>();
        for (int i = 0; i < 7; i++) {
            // Espaçado o bastante para não ser rajada: o que barra é o teto do minuto.
            Thread.sleep(700);
            status.add(transferirV2(bruno, null));
        }
        assertThat(status).containsExactly(200, 200, 200, 200, 200, 200, 429);
    }

    @Test
    void v2SomaAsContasDoMesmoDispositivo() throws Exception {
        String ana = entrar("v2", "ana@exemplo.com.br", "ana-senha-2026");
        String bruno = entrar("v2", "bruno@exemplo.com.br", "bruno-senha-2026");
        String aparelho = "aparelho-de-teste-0001";
        List<Integer> status = new ArrayList<>();
        for (int i = 0; i < 9; i++) {
            Thread.sleep(350);
            status.add(transferirV2(i % 2 == 0 ? ana : bruno, aparelho));
        }
        // Cada cliente fez no máximo 5, abaixo do teto dele; o aparelho chegou a 8.
        assertThat(status).containsExactly(200, 200, 200, 200, 200, 200, 200, 200, 429);
        assertThat(transferirV2(ana, "outro-aparelho-0002")).isEqualTo(200);
    }
}
