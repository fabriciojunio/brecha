package br.com.brecha.seguranca;

/** Autenticado, mas sem direito ao recurso: vira 403 no /v2. */
public class Proibido extends RuntimeException {

    public Proibido() {
        super("Acesso negado");
    }
}
