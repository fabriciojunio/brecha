package br.com.brecha.dominio;

/** Recusa por regra do banco: vira 422 nas duas versões da API. */
public class RegraDeNegocio extends RuntimeException {

    public RegraDeNegocio(String mensagem) {
        super(mensagem);
    }
}
