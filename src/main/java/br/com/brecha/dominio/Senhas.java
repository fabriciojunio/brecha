package br.com.brecha.dominio;

import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Hash de senha com PBKDF2-HMAC-SHA256, da própria JDK.
 *
 * <p>O hash não é uma das falhas deste projeto; ele está aqui para o
 * vazamento do BRECHA-003 mostrar um hash de verdade, e não texto puro.
 */
@Component
public class Senhas {

    // Recomendação da OWASP para PBKDF2-HMAC-SHA256 (Password Storage Cheat Sheet).
    private static final int ITERACOES = 600_000;
    private static final SecureRandom ALEATORIO = new SecureRandom();

    public String hash(String senha) {
        byte[] sal = new byte[16];
        ALEATORIO.nextBytes(sal);
        return Base64.getEncoder().encodeToString(sal) + "$" + Base64.getEncoder().encodeToString(derivar(senha, sal));
    }

    public boolean confere(String senha, String guardado) {
        String[] partes = guardado.split("\\$");
        byte[] sal = Base64.getDecoder().decode(partes[0]);
        byte[] esperado = Base64.getDecoder().decode(partes[1]);
        // Comparação em tempo constante: o tempo não entrega quantos bytes batem.
        return MessageDigest.isEqual(derivar(senha, sal), esperado);
    }

    private static byte[] derivar(String senha, byte[] sal) {
        try {
            var spec = new PBEKeySpec(senha.toCharArray(), sal, ITERACOES, 256);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("PBKDF2 indisponível na JDK", e);
        }
    }
}
