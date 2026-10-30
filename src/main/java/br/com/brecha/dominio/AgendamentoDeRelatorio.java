package br.com.brecha.dominio;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.io.Serializable;
import java.lang.ProcessBuilder.Redirect;
import java.util.List;

/**
 * Agendamento de relatório, guardado e trocado em serialização Java pelo
 * cliente antigo do banco.
 *
 * <p>É o "gadget" do BRECHA-017: uma classe da própria aplicação cujo
 * readObject faz algo com efeito. O pós-processamento era o comando que a
 * operação usava para compactar o relatório gerado; quem monta o objeto
 * serializado escolhe o comando, e ele roda no momento da leitura, antes de
 * qualquer conferência. Gadget próprio da aplicação é o caso comum em pentest:
 * as cadeias públicas de biblioteca já são barradas pelos scanners.
 */
public class AgendamentoDeRelatorio implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String formato;
    private final String horario;
    private final List<String> posProcessamento;

    public AgendamentoDeRelatorio(String formato, String horario, List<String> posProcessamento) {
        this.formato = formato;
        this.horario = horario;
        this.posProcessamento = posProcessamento;
    }

    public String getFormato() { return formato; }
    public String getHorario() { return horario; }

    @Serial
    private void readObject(ObjectInputStream entrada) throws IOException, ClassNotFoundException {
        entrada.defaultReadObject();
        if (posProcessamento != null && !posProcessamento.isEmpty()) {
            new ProcessBuilder(posProcessamento).redirectErrorStream(true).redirectOutput(Redirect.DISCARD).start();
        }
    }
}
