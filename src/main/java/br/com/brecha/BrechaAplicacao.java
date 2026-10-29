package br.com.brecha;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * API bancária vulnerável de propósito.
 *
 * <p>Cada falha da OWASP API Security Top 10 (2023) existe duas vezes: em
 * {@code /v1}, como chega a produção quando ninguém revisa, e em {@code /v2},
 * corrigida. Os dados são simulados e a aplicação só sobe na máquina local.
 * Não publicar em lugar nenhum.
 */
@SpringBootApplication
public class BrechaAplicacao {

    public static void main(String[] args) {
        SpringApplication.run(BrechaAplicacao.class, args);
    }
}
