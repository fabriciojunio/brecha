package br.com.brecha.seguranca;

import br.com.brecha.dominio.Cliente;

/** Quem está chamando, segundo o token. */
public record Sessao(long clienteId, Cliente.Perfil perfil) {

    public boolean admin() {
        return perfil == Cliente.Perfil.ADMIN;
    }
}
