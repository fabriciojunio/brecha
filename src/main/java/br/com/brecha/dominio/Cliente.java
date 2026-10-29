package br.com.brecha.dominio;

import java.math.BigDecimal;

/**
 * Cliente do banco. Mutável de propósito: é assim que o {@code /v1} deixa o
 * corpo da requisição escrever em qualquer campo (BRECHA-003).
 */
public class Cliente {

    public enum Perfil { CLIENTE, ADMIN }

    private final long id;
    private String nome;
    private final String cpf;
    private String email;
    private final String senhaHash;
    private Perfil perfil;
    private BigDecimal limiteDeCredito;

    public Cliente(long id, String nome, String cpf, String email, String senhaHash,
                   Perfil perfil, BigDecimal limiteDeCredito) {
        this.id = id;
        this.nome = nome;
        this.cpf = cpf;
        this.email = email;
        this.senhaHash = senhaHash;
        this.perfil = perfil;
        this.limiteDeCredito = limiteDeCredito;
    }

    public long getId() { return id; }
    public String getNome() { return nome; }
    public String getCpf() { return cpf; }
    public String getEmail() { return email; }
    public String getSenhaHash() { return senhaHash; }
    public Perfil getPerfil() { return perfil; }
    public BigDecimal getLimiteDeCredito() { return limiteDeCredito; }

    public void setNome(String nome) { this.nome = nome; }
    public void setEmail(String email) { this.email = email; }
    public void setPerfil(Perfil perfil) { this.perfil = perfil; }
    public void setLimiteDeCredito(BigDecimal limite) { this.limiteDeCredito = limite; }

    /** CPF com só os dois últimos dígitos à mostra, como sai no extrato de banco. */
    public String cpfMascarado() {
        return "***.***.***-" + cpf.substring(cpf.length() - 2);
    }
}
