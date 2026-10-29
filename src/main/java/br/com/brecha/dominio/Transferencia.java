package br.com.brecha.dominio;

import java.math.BigDecimal;
import java.time.Instant;

public record Transferencia(long id, long origem, long destino, BigDecimal valor, Instant quando) {
}
