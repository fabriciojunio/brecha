package br.com.brecha.api.v0;

import br.com.brecha.dominio.Banco;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * BRECHA-009: a primeira versão da API, de antes da autenticação. Saiu da
 * documentação quando o /v1 entrou, e ninguém desligou a rota.
 *
 * <p>A correção é tirar do ar. Aqui ela vira a propriedade
 * {@code brecha.legado.ativo}: ligada no laboratório, para o achado existir,
 * e o teste do reteste prova que desligada a rota some.
 */
@RestController
@ConditionalOnProperty(name = "brecha.legado.ativo", havingValue = "true")
public class ApiLegada {

    private final Banco banco;

    public ApiLegada(Banco banco) {
        this.banco = banco;
    }

    @GetMapping("/v0/clientes")
    public List<Map<String, Object>> clientes() {
        return banco.clientes().stream()
                .map(c -> Map.<String, Object>of("id", c.getId(), "nome", c.getNome(), "cpf", c.getCpf(), "email", c.getEmail()))
                .toList();
    }
}
