package br.com.brecha.api.v1;

import br.com.brecha.dominio.Banco;
import br.com.brecha.dominio.Cliente;
import br.com.brecha.dominio.Conta;
import br.com.brecha.dominio.Senhas;
import br.com.brecha.dominio.Transferencia;
import br.com.brecha.seguranca.NaoAutenticado;
import br.com.brecha.seguranca.Sessao;
import br.com.brecha.seguranca.TokenSemAssinatura;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.math.BigDecimal;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * A API como ela chega a produção quando ninguém revisa. Cada método aponta
 * o achado do relatório (docs/relatorio-pentest.md) que ele contém.
 */
@RestController
@RequestMapping("/v1")
public class ApiVulneravel {

    private final Banco banco;
    private final Senhas senhas;
    private final TokenSemAssinatura tokens;
    private final HttpClient http = HttpClient.newHttpClient();

    public ApiVulneravel(Banco banco, Senhas senhas, TokenSemAssinatura tokens) {
        this.banco = banco;
        this.senhas = senhas;
        this.tokens = tokens;
    }

    public record Login(String email, String senha) { }

    /** BRECHA-002: devolve um token sem assinatura. */
    @PostMapping("/sessoes")
    public Map<String, String> entrar(@RequestBody Login login) {
        Cliente cliente = banco.clientePorEmail(login.email())
                .filter(c -> senhas.confere(login.senha(), c.getSenhaHash()))
                .orElseThrow(NaoAutenticado::new);
        return Map.of("token", tokens.emitir(cliente));
    }

    /** BRECHA-001: devolve a conta pelo id da URL, sem conferir de quem é. */
    @GetMapping("/contas/{id}")
    public Map<String, Object> conta(@RequestHeader(value = "Authorization", required = false) String auth,
                                     @PathVariable long id) {
        sessao(auth);
        Conta conta = banco.conta(id).orElseThrow();
        return Map.of("id", conta.getId(), "clienteId", conta.getClienteId(), "saldo", conta.getSaldo());
    }

    /** BRECHA-003: devolve a entidade inteira, com CPF completo e hash de senha. */
    @GetMapping("/clientes/me")
    public Cliente eu(@RequestHeader(value = "Authorization", required = false) String auth) {
        return banco.cliente(sessao(auth).clienteId()).orElseThrow();
    }

    /**
     * BRECHA-003: copia todo campo do corpo para a entidade. O atalho serve
     * para nome e e-mail e também escreve perfil e limite de crédito.
     */
    @PatchMapping("/clientes/me")
    public Cliente atualizar(@RequestHeader(value = "Authorization", required = false) String auth,
                             @RequestBody Map<String, Object> campos) {
        Cliente cliente = banco.cliente(sessao(auth).clienteId()).orElseThrow();
        new BeanWrapperImpl(cliente).setPropertyValues(campos);
        return cliente;
    }

    public record Linha(LocalDate dia, BigDecimal saldo) { }

    /** BRECHA-004: monta quantos dias de extrato o cliente pedir, sem teto. */
    @GetMapping("/contas/{id}/extrato")
    public List<Linha> extrato(@RequestHeader(value = "Authorization", required = false) String auth,
                               @PathVariable long id, @RequestParam int dias) {
        sessao(auth);
        Conta conta = banco.conta(id).orElseThrow();
        List<Linha> linhas = new ArrayList<>(dias);
        LocalDate hoje = LocalDate.now();
        for (int i = 0; i < dias; i++) {
            linhas.add(new Linha(hoje.minusDays(i), conta.getSaldo()));
        }
        return linhas;
    }

    /** BRECHA-005: rota de administração que só confere se há sessão. */
    @GetMapping("/admin/clientes")
    public List<Cliente> todosOsClientes(@RequestHeader(value = "Authorization", required = false) String auth) {
        sessao(auth);
        return banco.clientes();
    }

    public record PedidoDeTransferencia(long origem, long destino, BigDecimal valor) { }

    /**
     * BRECHA-001 e BRECHA-006: a conta de origem vem do corpo, sem conferir
     * o dono, e a transferência não é atômica nem recusa valor negativo.
     */
    @PostMapping("/transferencias")
    public Transferencia transferir(@RequestHeader(value = "Authorization", required = false) String auth,
                                    @RequestBody PedidoDeTransferencia pedido) {
        sessao(auth);
        Conta origem = banco.conta(pedido.origem()).orElseThrow();
        Conta destino = banco.conta(pedido.destino()).orElseThrow();
        return banco.transferirSemTrava(origem, destino, pedido.valor());
    }

    public record Importacao(String url) { }

    /** BRECHA-007: busca qualquer endereço que o cliente mandar. */
    @PostMapping("/comprovantes/importar")
    public Map<String, Object> importar(@RequestHeader(value = "Authorization", required = false) String auth,
                                        @RequestBody Importacao pedido) throws Exception {
        sessao(auth);
        HttpResponse<String> resposta = http.send(
                HttpRequest.newBuilder(URI.create(pedido.url())).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return Map.of("status", resposta.statusCode(), "conteudo", resposta.body());
    }

    private Sessao sessao(String auth) {
        if (auth == null || !auth.startsWith("Bearer ")) {
            throw new NaoAutenticado();
        }
        return tokens.ler(auth.substring(7)).orElseThrow(NaoAutenticado::new);
    }

    /** Usado pelo tratador de erro do /v1. */
    static boolean naoEncontrado(Throwable e) {
        return e instanceof NoSuchElementException;
    }
}
