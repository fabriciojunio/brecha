package br.com.brecha.seguranca;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

@Configuration
public class Configuracao {

    /** Relógio injetado, para o teste conseguir vencer um token sem esperar. */
    @Bean
    Clock relogio() {
        return Clock.systemUTC();
    }
}
