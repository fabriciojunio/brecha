package br.com.brecha.seguranca;

import br.com.brecha.dominio.Cliente;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Token do /v1 (BRECHA-002): "clienteId:perfil" em Base64, sem assinatura.
 *
 * <p>Base64 é codificação, não proteção. Quem decodifica o próprio token
 * entende o formato e escreve outro com o id e o perfil que quiser.
 */
@Component
public class TokenSemAssinatura {

    public String emitir(Cliente cliente) {
        String conteudo = cliente.getId() + ":" + cliente.getPerfil();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(conteudo.getBytes(StandardCharsets.UTF_8));
    }

    public Optional<Sessao> ler(String token) {
        try {
            String[] partes = new String(Base64.getUrlDecoder().decode(token), StandardCharsets.UTF_8).split(":");
            return Optional.of(new Sessao(Long.parseLong(partes[0]), Cliente.Perfil.valueOf(partes[1])));
        } catch (RuntimeException e) {
            return Optional.empty();
        }
    }
}
