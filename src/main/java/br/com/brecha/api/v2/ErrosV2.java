package br.com.brecha.api.v2;

import br.com.brecha.dominio.RegraDeNegocio;
import br.com.brecha.seguranca.NaoAutenticado;
import br.com.brecha.seguranca.Proibido;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.util.NoSuchElementException;
import java.util.UUID;

/**
 * Correção do BRECHA-008: o cliente recebe só o status, uma frase genérica e
 * um identificador; a pilha vai para o log, com o mesmo identificador, para
 * o suporte achar o erro sem expô-lo.
 */
@RestControllerAdvice(basePackages = "br.com.brecha.api.v2")
public class ErrosV2 {

    private static final Logger log = LoggerFactory.getLogger(ErrosV2.class);

    @ExceptionHandler(NaoAutenticado.class)
    ProblemDetail naoAutenticado() {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Autenticação necessária");
    }

    @ExceptionHandler(Proibido.class)
    ProblemDetail proibido() {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Acesso negado");
    }

    @ExceptionHandler(NoSuchElementException.class)
    ProblemDetail naoEncontrado() {
        return ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, "Recurso não encontrado");
    }

    @ExceptionHandler(RegraDeNegocio.class)
    ProblemDetail regra(RegraDeNegocio e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNPROCESSABLE_CONTENT, e.getMessage());
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HandlerMethodValidationException.class,
            ConstraintViolationException.class})
    ProblemDetail invalido() {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Requisição inválida");
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail inesperado(Exception e) {
        String id = UUID.randomUUID().toString();
        log.error("Erro inesperado {}", id, e);
        ProblemDetail problema = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno");
        problema.setProperty("identificador", id);
        return problema;
    }
}
