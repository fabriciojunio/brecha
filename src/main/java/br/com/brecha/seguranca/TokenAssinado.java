package br.com.brecha.seguranca;

import br.com.brecha.dominio.Cliente;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

/**
 * Token do /v2: "clienteId:perfil:expiraEm" mais a assinatura HMAC-SHA256.
 *
 * <p>Num sistema de verdade isto seria um JWT emitido por um provedor de
 * identidade. Aqui fica à mão, com a primitiva da JDK, para cada linha da
 * correção do BRECHA-002 ser visível: assinatura, validade e comparação em
 * tempo constante.
 */
@Component
public class TokenAssinado {

    static final Duration VALIDADE = Duration.ofMinutes(15);
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();

    private final byte[] segredo;
    private final Clock relogio;

    public TokenAssinado(@Value("${brecha.segredo}") String segredo, Clock relogio) {
        // HMAC-SHA256 com chave curta vira adivinhação. 32 bytes é o tamanho
        // da saída do SHA-256, o mínimo que a RFC 7518 pede para HS256.
        if (segredo == null || segredo.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("brecha.segredo precisa de pelo menos 32 bytes");
        }
        this.segredo = segredo.getBytes(StandardCharsets.UTF_8);
        this.relogio = relogio;
    }

    public String emitir(Cliente cliente) {
        long expira = relogio.instant().plus(VALIDADE).getEpochSecond();
        String conteudo = cliente.getId() + ":" + cliente.getPerfil() + ":" + expira;
        String c = B64.encodeToString(conteudo.getBytes(StandardCharsets.UTF_8));
        return c + "." + B64.encodeToString(assinar(c));
    }

    public Optional<Sessao> ler(String token) {
        try {
            String[] partes = token.split("\\.");
            if (partes.length != 2) {
                return Optional.empty();
            }
            byte[] recebida = Base64.getUrlDecoder().decode(partes[1]);
            if (!MessageDigest.isEqual(assinar(partes[0]), recebida)) {
                return Optional.empty();
            }
            String[] campos = new String(Base64.getUrlDecoder().decode(partes[0]), StandardCharsets.UTF_8).split(":");
            if (relogio.instant().getEpochSecond() >= Long.parseLong(campos[2])) {
                return Optional.empty();
            }
            return Optional.of(new Sessao(Long.parseLong(campos[0]), Cliente.Perfil.valueOf(campos[1])));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }

    private byte[] assinar(String conteudo) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(segredo, "HmacSHA256"));
            return mac.doFinal(conteudo.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HmacSHA256 indisponível na JDK", e);
        }
    }
}
