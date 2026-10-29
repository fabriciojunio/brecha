package br.com.brecha.seguranca;

/** Sem token, ou token que não vale: vira 401. */
public class NaoAutenticado extends RuntimeException {

    public NaoAutenticado() {
        super("Autenticação necessária");
    }
}
