package br.com.brecha.dominio;

import java.math.BigDecimal;
import java.util.concurrent.locks.ReentrantLock;

/** Conta corrente. O saldo só muda pelos métodos do {@link Banco}. */
public class Conta {

    private final long id;
    private final long clienteId;
    private BigDecimal saldo;
    // Trava por conta, usada só pelo /v2. Uma trava global serializaria o
    // banco inteiro; por conta, transferências entre contas diferentes correm
    // em paralelo.
    final ReentrantLock trava = new ReentrantLock();

    public Conta(long id, long clienteId, BigDecimal saldo) {
        this.id = id;
        this.clienteId = clienteId;
        this.saldo = saldo;
    }

    public long getId() { return id; }
    public long getClienteId() { return clienteId; }
    public synchronized BigDecimal getSaldo() { return saldo; }

    synchronized void creditar(BigDecimal valor) { saldo = saldo.add(valor); }
    synchronized void debitar(BigDecimal valor) { saldo = saldo.subtract(valor); }
}
