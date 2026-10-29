package br.com.brecha.dominio;

import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * O banco em memória, com dados simulados.
 *
 * <p>Sem banco de dados de propósito: as falhas daqui são de autorização e de
 * lógica, e nenhuma delas depende de SQL. Menos peça, menos coisa para
 * explicar.
 */
@Component
public class Banco {

    /** Atraso da consulta ao antifraude externo, como numa chamada de rede. */
    static final long ANTIFRAUDE_MS = 25;

    private final Map<Long, Cliente> clientes = new ConcurrentHashMap<>();
    private final Map<Long, Conta> contas = new ConcurrentHashMap<>();
    private final List<Transferencia> transferencias = Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong sequencia = new AtomicLong(1000);

    public Banco(Senhas senhas) {
        // Dados simulados. CPF gerado só para ter formato válido.
        adicionar(new Cliente(1, "Ana Souza", "52998224725", "ana@exemplo.com.br",
                senhas.hash("ana-senha-2026"), Cliente.Perfil.CLIENTE, new BigDecimal("1000.00")),
                new BigDecimal("500.00"));
        adicionar(new Cliente(2, "Bruno Lima", "11144477735", "bruno@exemplo.com.br",
                senhas.hash("bruno-senha-2026"), Cliente.Perfil.CLIENTE, new BigDecimal("2000.00")),
                new BigDecimal("8000.00"));
        adicionar(new Cliente(3, "Operação", "39053344705", "operacao@exemplo.com.br",
                senhas.hash("operacao-senha-2026"), Cliente.Perfil.ADMIN, BigDecimal.ZERO),
                BigDecimal.ZERO);
    }

    private void adicionar(Cliente cliente, BigDecimal saldo) {
        clientes.put(cliente.getId(), cliente);
        contas.put(cliente.getId() * 100, new Conta(cliente.getId() * 100, cliente.getId(), saldo));
    }

    public Optional<Cliente> cliente(long id) { return Optional.ofNullable(clientes.get(id)); }

    public Optional<Cliente> clientePorEmail(String email) {
        return clientes.values().stream().filter(c -> c.getEmail().equalsIgnoreCase(email)).findFirst();
    }

    public List<Cliente> clientes() { return List.copyOf(clientes.values()); }

    public Optional<Conta> conta(long id) { return Optional.ofNullable(contas.get(id)); }

    public Optional<Conta> contaDoCliente(long clienteId) {
        return contas.values().stream().filter(c -> c.getClienteId() == clienteId).findFirst();
    }

    public List<Transferencia> transferenciasDa(long contaId) {
        synchronized (transferencias) {
            return transferencias.stream()
                    .filter(t -> t.origem() == contaId || t.destino() == contaId)
                    .toList();
        }
    }

    /**
     * Transferência do /v1 (BRECHA-006). Confere o saldo, consulta o antifraude
     * e só depois debita. Duas requisições ao mesmo tempo passam as duas pela
     * conferência antes de qualquer débito, e o saldo fica negativo. Também
     * aceita valor negativo, que transfere dinheiro no sentido contrário.
     */
    public Transferencia transferirSemTrava(Conta origem, Conta destino, BigDecimal valor) {
        if (origem.getSaldo().compareTo(valor) < 0) {
            throw new RegraDeNegocio("Saldo insuficiente");
        }
        consultarAntifraude();
        origem.debitar(valor);
        destino.creditar(valor);
        return registrar(origem, destino, valor);
    }

    /**
     * Transferência do /v2. Valor positivo, e conferência e débito dentro da
     * trava da conta de origem: a segunda requisição só confere depois que a
     * primeira debitou.
     */
    public Transferencia transferir(Conta origem, Conta destino, BigDecimal valor) {
        if (valor.signum() <= 0) {
            throw new RegraDeNegocio("O valor tem que ser positivo");
        }
        if (origem.getId() == destino.getId()) {
            throw new RegraDeNegocio("Origem e destino são a mesma conta");
        }
        origem.trava.lock();
        try {
            if (origem.getSaldo().compareTo(valor) < 0) {
                throw new RegraDeNegocio("Saldo insuficiente");
            }
            consultarAntifraude();
            origem.debitar(valor);
        } finally {
            origem.trava.unlock();
        }
        destino.creditar(valor);
        return registrar(origem, destino, valor);
    }

    private Transferencia registrar(Conta origem, Conta destino, BigDecimal valor) {
        var t = new Transferencia(sequencia.incrementAndGet(), origem.getId(), destino.getId(), valor, Instant.now());
        transferencias.add(t);
        return t;
    }

    private static void consultarAntifraude() {
        try {
            Thread.sleep(ANTIFRAUDE_MS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RegraDeNegocio("Transferência interrompida");
        }
    }
}
