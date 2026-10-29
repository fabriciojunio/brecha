package br.com.brecha.api.v1;

import br.com.brecha.dominio.RegraDeNegocio;
import br.com.brecha.seguranca.NaoAutenticado;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.Map;

/**
 * BRECHA-008: o erro volta para o cliente com a classe da exceção, a mensagem
 * e a pilha inteira. Facilita a vida de quem depura, e de quem ataca.
 */
@RestControllerAdvice(basePackages = "br.com.brecha.api.v1")
public class ErrosV1 {

    @ExceptionHandler(NaoAutenticado.class)
    ResponseEntity<Map<String, String>> naoAutenticado(NaoAutenticado e) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("erro", e.getMessage()));
    }

    @ExceptionHandler(RegraDeNegocio.class)
    ResponseEntity<Map<String, String>> regra(RegraDeNegocio e) {
        return ResponseEntity.unprocessableEntity().body(Map.of("erro", e.getMessage()));
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Map<String, String>> qualquer(Exception e) {
        var pilha = new StringWriter();
        e.printStackTrace(new PrintWriter(pilha));
        HttpStatus status = ApiVulneravel.naoEncontrado(e) ? HttpStatus.NOT_FOUND : HttpStatus.INTERNAL_SERVER_ERROR;
        return ResponseEntity.status(status).body(Map.of(
                "erro", e.getClass().getName(),
                "mensagem", String.valueOf(e.getMessage()),
                "pilha", pilha.toString()));
    }
}
