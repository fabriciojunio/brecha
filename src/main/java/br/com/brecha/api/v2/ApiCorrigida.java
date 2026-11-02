package br.com.brecha.api.v2;

import br.com.brecha.dominio.Banco;
import br.com.brecha.dominio.Cliente;
import br.com.brecha.dominio.Conta;
import br.com.brecha.dominio.Senhas;
import br.com.brecha.dominio.Transferencia;
import br.com.brecha.seguranca.LimiteDeUso;
import br.com.brecha.seguranca.NaoAutenticado;
import br.com.brecha.seguranca.Proibido;
import br.com.brecha.seguranca.Sessao;
import br.com.brecha.seguranca.TokenAssinado;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;
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
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** A mesma API com cada achado corrigido. O comentário aponta o achado. */
@RestController
@Validated
@RequestMapping("/v2")
public class ApiCorrigida {

    /** Maior período de extrato numa chamada (BRECHA-004). */
    static final int DIAS_MAXIMOS = 90;
    /** Tentativas de login por e-mail antes de travar (BRECHA-002). */
    static final int TENTATIVAS = 5;

    private final Banco banco;
    private final Senhas senhas;
    private final TokenAssinado tokens;
    private final DestinoExterno destinos;
    private final LimiteDeUso limite;
    private final Map<String, Integer> falhasDeLogin = new ConcurrentHashMap<>();
    // BRECHA-007: sem seguir redirecionamento e com tempo limite.
    private final HttpClient http = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    public ApiCorrigida(Banco banco, Senhas senhas, TokenAssinado tokens, DestinoExterno destinos, LimiteDeUso limite) {
        this.banco = banco;
        this.senhas = senhas;
        this.tokens = tokens;
        this.destinos = destinos;
        this.limite = limite;
    }

    public record Login(@NotBlank @Email String email, @NotBlank String senha) { }

    /**
     * BRECHA-002: token assinado e com validade, e trava por e-mail depois de
     * cinco erros. A resposta de erro é a mesma para e-mail inexistente e
     * senha errada.
     */
    @PostMapping("/sessoes")
    public Map<String, String> entrar(@Valid @RequestBody Login login) {
        String chave = login.email().toLowerCase();
        if (falhasDeLogin.getOrDefault(chave, 0) >= TENTATIVAS) {
            throw new NaoAutenticado();
        }
        var cliente = banco.clientePorEmail(chave).filter(c -> senhas.confere(login.senha(), c.getSenhaHash()));
        if (cliente.isEmpty()) {
            falhasDeLogin.merge(chave, 1, Integer::sum);
            throw new NaoAutenticado();
        }
        falhasDeLogin.remove(chave);
        return Map.of("token", tokens.emitir(cliente.get()));
    }

    /** BRECHA-001: só o dono da conta, ou o administrador, vê a conta. */
    @GetMapping("/contas/{id}")
    public Map<String, Object> conta(@RequestHeader(value = "Authorization", required = false) String auth,
                                     @PathVariable long id) {
        Conta conta = contaDoDono(sessao(auth), id);
        return Map.of("id", conta.getId(), "saldo", conta.getSaldo());
    }

    public record Perfil(long id, String nome, String cpf, String email) {
        static Perfil de(Cliente c) {
            return new Perfil(c.getId(), c.getNome(), c.cpfMascarado(), c.getEmail());
        }
    }

    /** BRECHA-003: resposta com campos escolhidos, CPF mascarado e sem hash. */
    @GetMapping("/clientes/me")
    public Perfil eu(@RequestHeader(value = "Authorization", required = false) String auth) {
        return Perfil.de(banco.cliente(sessao(auth).clienteId()).orElseThrow());
    }

    public record Atualizacao(@Size(min = 3, max = 100) String nome, @Email String email) { }

    /** BRECHA-003: o corpo só tem nome e e-mail; perfil e limite não existem nele. */
    @PatchMapping("/clientes/me")
    public Perfil atualizar(@RequestHeader(value = "Authorization", required = false) String auth,
                            @Valid @RequestBody Atualizacao dados) {
        Cliente cliente = banco.cliente(sessao(auth).clienteId()).orElseThrow();
        if (dados.nome() != null) {
            cliente.setNome(dados.nome());
        }
        if (dados.email() != null) {
            cliente.setEmail(dados.email());
        }
        return Perfil.de(cliente);
    }

    public record Linha(LocalDate dia, BigDecimal saldo) { }

    /** BRECHA-004: no máximo 90 dias por chamada. */
    @GetMapping("/contas/{id}/extrato")
    public List<Linha> extrato(@RequestHeader(value = "Authorization", required = false) String auth,
                               @PathVariable long id,
                               @RequestParam @Min(1) @Max(DIAS_MAXIMOS) int dias) {
        Conta conta = contaDoDono(sessao(auth), id);
        List<Linha> linhas = new ArrayList<>(dias);
        LocalDate hoje = LocalDate.now();
        for (int i = 0; i < dias; i++) {
            linhas.add(new Linha(hoje.minusDays(i), conta.getSaldo()));
        }
        return linhas;
    }

    /** BRECHA-005: perfil conferido pela rota, e a lista sai sem documento nem hash. */
    @GetMapping("/admin/clientes")
    public List<Perfil> todosOsClientes(@RequestHeader(value = "Authorization", required = false) String auth) {
        if (!sessao(auth).admin()) {
            throw new Proibido();
        }
        return banco.clientes().stream().map(Perfil::de).toList();
    }

    public record PedidoDeTransferencia(@NotNull Long destino, @NotNull @Positive BigDecimal valor) { }

    /** Identificador do aparelho que o app manda; fora do formato, vale o cliente. */
    private static final java.util.regex.Pattern DISPOSITIVO = java.util.regex.Pattern.compile("[A-Za-z0-9-]{8,64}");

    /**
     * BRECHA-001 e BRECHA-006: a origem é sempre a conta de quem está logado,
     * o valor tem que ser positivo e a transferência é atômica. BRECHA-019:
     * limite por cliente, por dispositivo e por ritmo antes de mexer no saldo.
     */
    @PostMapping("/transferencias")
    public Transferencia transferir(@RequestHeader(value = "Authorization", required = false) String auth,
                                    @RequestHeader(value = "X-Dispositivo", required = false) String dispositivo,
                                    @Valid @RequestBody PedidoDeTransferencia pedido) {
        Sessao sessao = sessao(auth);
        limite.registrar(sessao.clienteId(), dispositivo != null && DISPOSITIVO.matcher(dispositivo).matches()
                ? dispositivo : "cliente-" + sessao.clienteId());
        Conta origem = banco.contaDoCliente(sessao.clienteId()).orElseThrow();
        Conta destino = banco.conta(pedido.destino()).orElseThrow();
        return banco.transferir(origem, destino, pedido.valor());
    }

    public record Importacao(@NotBlank String url) { }

    /** BRECHA-007: só busca emissor de comprovante da lista, fora da rede interna. */
    @PostMapping("/comprovantes/importar")
    public Map<String, Object> importar(@RequestHeader(value = "Authorization", required = false) String auth,
                                        @Valid @RequestBody Importacao pedido) throws Exception {
        sessao(auth);
        var uri = destinos.validar(pedido.url());
        HttpResponse<String> resposta = http.send(
                HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(10)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        return Map.of("status", resposta.statusCode());
    }

    /**
     * BRECHA-018: só quem pagou estorna, uma vez, e sempre o valor original.
     * Transferência de outro cliente responde 404, como conta de outro cliente.
     */
    @PostMapping("/transferencias/{id}/estorno")
    public Transferencia estornar(@RequestHeader(value = "Authorization", required = false) String auth,
                                  @PathVariable long id) {
        Conta conta = banco.contaDoCliente(sessao(auth).clienteId()).orElseThrow();
        Transferencia original = banco.transferencia(id)
                .filter(t -> t.origem() == conta.getId())
                .orElseThrow();
        return banco.estornar(original);
    }

    public enum Formato { PDF, CSV }

    public record Agendamento(@NotNull Formato formato,
                              @NotNull @Pattern(regexp = "([01]\\d|2[0-3]):[0-5]\\d") String horario) { }

    /**
     * BRECHA-017: JSON com dois campos validados, e nada de serialização Java.
     * O comando de pós-processamento saiu do contrato: quem decide o que roda
     * no servidor é o servidor.
     */
    @PostMapping("/agendamentos")
    public Map<String, Object> agendar(@RequestHeader(value = "Authorization", required = false) String auth,
                                       @Valid @RequestBody Agendamento pedido) {
        sessao(auth);
        return Map.of("formato", pedido.formato(), "horario", pedido.horario());
    }

    private Conta contaDoDono(Sessao sessao, long contaId) {
        Conta conta = banco.conta(contaId).orElseThrow();
        if (conta.getClienteId() != sessao.clienteId() && !sessao.admin()) {
            // 404 e não 403: quem não é dono não precisa saber que a conta existe.
            throw new java.util.NoSuchElementException();
        }
        return conta;
    }

    private Sessao sessao(String auth) {
        if (auth == null || !auth.startsWith("Bearer ")) {
            throw new NaoAutenticado();
        }
        return tokens.ler(auth.substring(7)).orElseThrow(NaoAutenticado::new);
    }
}
