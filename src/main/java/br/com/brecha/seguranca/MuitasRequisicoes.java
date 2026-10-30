package br.com.brecha.seguranca;

import java.time.Duration;

/** Limite de uso estourado: vira 429 com Retry-After no /v2. */
public class MuitasRequisicoes extends RuntimeException {

    private final Duration espera;

    public MuitasRequisicoes(Duration espera) {
        super("Muitas requisições");
        this.espera = espera;
    }

    /** Segundos até poder tentar de novo, arredondado para cima e nunca zero. */
    public long segundos() {
        return Math.max(1, (espera.toMillis() + 999) / 1000);
    }
}
