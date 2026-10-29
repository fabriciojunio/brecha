package br.com.brecha.api.v2;

import br.com.brecha.dominio.RegraDeNegocio;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * Correção do BRECHA-007. Antes de buscar um endereço vindo do cliente:
 *
 * <ol>
 *   <li>só HTTPS;</li>
 *   <li>só os hosts da lista do banco;</li>
 *   <li>o nome é resolvido e nenhum IP pode ser interno. É isso que pega o
 *       host da lista que alguém faça apontar para 127.0.0.1 ou para o
 *       endereço de metadados da nuvem (169.254.169.254).</li>
 * </ol>
 *
 * <p>O cliente HTTP do /v2 não segue redirecionamento: sem isso, um host
 * permitido devolveria 302 para um interno e passaria pela conferência.
 */
@Component
public class DestinoExterno {

    private final Set<String> hostsPermitidos;

    public DestinoExterno(@Value("${brecha.comprovantes.hosts}") Set<String> hostsPermitidos) {
        this.hostsPermitidos = hostsPermitidos;
    }

    public URI validar(String endereco) {
        URI uri;
        try {
            uri = URI.create(endereco);
        } catch (IllegalArgumentException e) {
            throw new RegraDeNegocio("Endereço inválido");
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
            throw new RegraDeNegocio("Só endereços https são aceitos");
        }
        if (!hostsPermitidos.contains(uri.getHost().toLowerCase())) {
            throw new RegraDeNegocio("Host fora da lista de emissores de comprovante");
        }
        try {
            for (InetAddress ip : InetAddress.getAllByName(uri.getHost())) {
                if (ip.isLoopbackAddress() || ip.isSiteLocalAddress() || ip.isLinkLocalAddress()
                        || ip.isAnyLocalAddress() || ip.isMulticastAddress()) {
                    throw new RegraDeNegocio("O host aponta para a rede interna");
                }
            }
        } catch (UnknownHostException e) {
            throw new RegraDeNegocio("Host não encontrado");
        }
        return uri;
    }
}
