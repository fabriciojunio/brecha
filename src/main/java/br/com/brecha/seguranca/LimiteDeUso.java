package br.com.brecha.seguranca;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limite de transferências do /v2 (BRECHA-019): por cliente, por dispositivo e
 * por ritmo.
 *
 * <p>O limite por cliente segura quem tomou uma conta e tenta esvaziá-la em
 * muitas transferências pequenas. O por dispositivo soma todas as contas do
 * mesmo aparelho, o desenho de conta laranja. O de ritmo pega o robô: gente
 * não faz cinco transferências em dois segundos, e quem faz fica bloqueado por
 * um minuto.
 *
 * <p>Em memória, como o resto do laboratório. Com mais de uma instância, os
 * contadores iriam para um armazenamento compartilhado (Redis, por exemplo).
 */
@Component
public class LimiteDeUso {

    static final Duration MINUTO = Duration.ofMinutes(1);
    static final Duration JANELA_DE_RAJADA = Duration.ofSeconds(2);
    static final Duration BLOQUEIO_POR_RAJADA = Duration.ofMinutes(1);

    private final int porCliente;
    private final int porDispositivo;
    private final int rajada;
    private final Clock relogio;
    private final Map<String, Deque<Instant>> historico = new ConcurrentHashMap<>();
    private final Map<String, Instant> bloqueadosAte = new ConcurrentHashMap<>();

    public LimiteDeUso(@Value("${brecha.limite.transferencias-por-minuto:10}") int porCliente,
                       @Value("${brecha.limite.transferencias-por-dispositivo:20}") int porDispositivo,
                       @Value("${brecha.limite.rajada:5}") int rajada,
                       Clock relogio) {
        this.porCliente = porCliente;
        this.porDispositivo = porDispositivo;
        this.rajada = rajada;
        this.relogio = relogio;
    }

    /**
     * Registra uma transferência ou recusa com o tempo de espera. Tudo dentro
     * de uma trava só: conferir e registrar separados deixariam duas
     * requisições simultâneas passarem pelo mesmo último lugar.
     */
    public synchronized void registrar(long clienteId, String dispositivo) {
        Instant agora = relogio.instant();
        String cliente = "cliente:" + clienteId;
        String aparelho = "dispositivo:" + dispositivo;

        for (String chave : new String[] {cliente, aparelho}) {
            Instant ate = bloqueadosAte.get(chave);
            if (ate != null && agora.isBefore(ate)) {
                throw new MuitasRequisicoes(Duration.between(agora, ate));
            }
        }

        Deque<Instant> doCliente = recentes(cliente, agora);
        Deque<Instant> doAparelho = recentes(aparelho, agora);
        long naRajada = doCliente.stream().filter(t -> t.isAfter(agora.minus(JANELA_DE_RAJADA))).count();
        if (naRajada >= rajada - 1) {
            bloqueadosAte.put(cliente, agora.plus(BLOQUEIO_POR_RAJADA));
            throw new MuitasRequisicoes(BLOQUEIO_POR_RAJADA);
        }
        if (doCliente.size() >= porCliente) {
            throw new MuitasRequisicoes(Duration.between(agora, doCliente.peekFirst().plus(MINUTO)));
        }
        if (doAparelho.size() >= porDispositivo) {
            throw new MuitasRequisicoes(Duration.between(agora, doAparelho.peekFirst().plus(MINUTO)));
        }
        doCliente.addLast(agora);
        doAparelho.addLast(agora);
    }

    private Deque<Instant> recentes(String chave, Instant agora) {
        Deque<Instant> fila = historico.computeIfAbsent(chave, k -> new ArrayDeque<>());
        while (!fila.isEmpty() && !fila.peekFirst().isAfter(agora.minus(MINUTO))) {
            fila.removeFirst();
        }
        return fila;
    }
}
