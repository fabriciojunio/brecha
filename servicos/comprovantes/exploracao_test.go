package main

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// Cada falha tem a exploração no /v1 e a prova do bloqueio no /v2, como os
// testes do serviço principal. Dados simulados.

func chavesDeTeste() Chaves {
	return Chaves{Cifra: bytes.Repeat([]byte{7}, 32), Assinatura: bytes.Repeat([]byte{9}, 32)}
}

func emitirPorHTTP(t *testing.T, srv *httptest.Server, versao, pagador string, valor int64) (int, Comprovante) {
	t.Helper()
	corpo, _ := json.Marshal(pedido{Destino: "conta 300", Pagador: pagador, ValorCentavos: valor})
	resp, err := http.Post(srv.URL+"/"+versao+"/comprovantes", "application/json", bytes.NewReader(corpo))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var c Comprovante
	_ = json.NewDecoder(resp.Body).Decode(&c)
	return resp.StatusCode, c
}

func consultarPorHTTP(t *testing.T, srv *httptest.Server, versao, id string) Comprovante {
	t.Helper()
	resp, err := http.Get(srv.URL + "/" + versao + "/comprovantes/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var c Comprovante
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

func xor(a, b []byte) []byte {
	n := min(len(a), len(b))
	saida := make([]byte, n)
	for i := range n {
		saida[i] = a[i] ^ b[i]
	}
	return saida
}

// BRECHA-010. A Ana sabe o próprio nome, que está no comprovante dela, e lê o
// comprovante do Bruno pelo link público. Com o nonce repetido, o XOR dos dois
// textos cifrados com o texto dela devolve o texto do Bruno, sem a chave.
func TestBrecha010NonceRepetidoRevelaOPagadorDeOutroComprovante(t *testing.T) {
	srv := httptest.NewServer(novoServico(chavesDeTeste()).rotas())
	defer srv.Close()

	const pagadorAna = "Ana Souza, CPF 111.111.111-11"
	const pagadorBruno = "Bruno Lima, CPF 222.222.222-22"
	_, daAna := emitirPorHTTP(t, srv, "v1", pagadorAna, 5_000)
	_, doBruno := emitirPorHTTP(t, srv, "v1", pagadorBruno, 7_000)

	publico := consultarPorHTTP(t, srv, "v1", doBruno.ID)
	cifradoAna, _ := hex.DecodeString(daAna.PagadorCifrado)
	cifradoBruno, _ := hex.DecodeString(publico.PagadorCifrado)

	recuperado := string(xor(xor(cifradoAna, cifradoBruno), []byte(pagadorAna)))
	if recuperado != pagadorBruno[:len(recuperado)] || len(recuperado) < len("Bruno Lima, CPF 222.222.222") {
		t.Fatalf("esperava recuperar o pagador do Bruno, veio %q", recuperado)
	}
}

func TestBrecha010V2UsaNonceNovoECifraDiferente(t *testing.T) {
	srv := httptest.NewServer(novoServico(chavesDeTeste()).rotas())
	defer srv.Close()

	const pagadorAna = "Ana Souza, CPF 111.111.111-11"
	const pagadorBruno = "Bruno Lima, CPF 222.222.222-22"
	_, daAna := emitirPorHTTP(t, srv, "v2", pagadorAna, 5_000)
	_, doBruno := emitirPorHTTP(t, srv, "v2", pagadorBruno, 7_000)
	cifradoAna, _ := hex.DecodeString(daAna.PagadorCifrado)
	cifradoBruno, _ := hex.DecodeString(consultarPorHTTP(t, srv, "v2", doBruno.ID).PagadorCifrado)

	// O ataque do v1, repetido aqui, só devolve lixo.
	if recuperado := string(xor(xor(cifradoAna[12:], cifradoBruno[12:]), []byte(pagadorAna))); strings.Contains(recuperado, "Bruno") {
		t.Fatalf("o ataque do nonce repetido ainda funciona no v2: %q", recuperado)
	}
	// Mesmo pagador duas vezes: cifras diferentes, e o banco ainda lê.
	_, outra := emitirPorHTTP(t, srv, "v2", pagadorAna, 5_000)
	if outra.PagadorCifrado == daAna.PagadorCifrado {
		t.Fatal("dois comprovantes do mesmo pagador com a mesma cifra")
	}
	if texto, err := DecifrarV2(chavesDeTeste().Cifra, outra.PagadorCifrado); err != nil || texto != pagadorAna {
		t.Fatalf("o banco não lê o próprio comprovante: %q %v", texto, err)
	}
}

// nanossegundosPorComparacao mede com testing.Benchmark, que repete a chamada
// até o tempo total ficar bem acima da resolução do relógio (no Windows ela é
// grossa). Cinco medições e fica a menor: ruído da máquina só soma tempo,
// nunca tira, então o mínimo é o que mais se aproxima do custo real.
func nanossegundosPorComparacao(t *testing.T, comparar func([]byte, []byte) bool, recebida, esperada []byte) float64 {
	t.Helper()
	medidas := make([]float64, 5)
	for m := range medidas {
		resultado := false
		r := testing.Benchmark(func(b *testing.B) {
			for b.Loop() {
				resultado = comparar(recebida, esperada) != resultado
			}
		})
		_ = resultado
		medidas[m] = float64(r.T.Nanoseconds()) / float64(r.N)
	}
	menor := slices.Min(medidas)
	if menor <= 0 {
		t.Fatalf("medição sem resolução: %v", medidas)
	}
	return menor
}

func assinaturaComPrefixoCerto(esperada []byte, certos int) []byte {
	tentativa := bytes.Repeat([]byte{0xAA}, len(esperada))
	copy(tentativa, esperada[:certos])
	if certos < len(esperada) && tentativa[certos] == esperada[certos] {
		tentativa[certos] ^= 0xFF
	}
	return tentativa
}

// BRECHA-011. Com 31 bytes certos a comparação do v1 demora muito mais que
// com nenhum: é essa diferença que deixa descobrir a assinatura byte a byte.
func TestBrecha011ComparacaoDoV1VazaQuantosBytesEstaoCertos(t *testing.T) {
	esperada := assinar(chavesDeTeste().Assinatura, Comprovante{ID: "c000001", Destino: "conta 300", ValorCentavos: 100})
	nenhum := nanossegundosPorComparacao(t, compararV1, assinaturaComPrefixoCerto(esperada, 0), esperada)
	quase := nanossegundosPorComparacao(t, compararV1, assinaturaComPrefixoCerto(esperada, 31), esperada)
	t.Logf("v1: 0 bytes certos %.1f ns, 31 bytes certos %.1f ns", nenhum, quase)
	if quase < 2*nenhum {
		t.Fatalf("esperava a comparação com 31 bytes certos pelo menos 2x mais lenta: %.1f contra %.1f ns", quase, nenhum)
	}
}

func TestBrecha011ComparacaoDoV2NaoDependeDoPrefixo(t *testing.T) {
	esperada := assinar(chavesDeTeste().Assinatura, Comprovante{ID: "c000001", Destino: "conta 300", ValorCentavos: 100})
	nenhum := nanossegundosPorComparacao(t, hmac.Equal, assinaturaComPrefixoCerto(esperada, 0), esperada)
	quase := nanossegundosPorComparacao(t, hmac.Equal, assinaturaComPrefixoCerto(esperada, 31), esperada)
	t.Logf("v2: 0 bytes certos %.1f ns, 31 bytes certos %.1f ns", nenhum, quase)
	if razao := quase / nenhum; razao > 1.5 || razao < 0.67 {
		t.Fatalf("o tempo da comparação do v2 mudou com o prefixo: %.1f contra %.1f ns", quase, nenhum)
	}
}

func TestBrecha011AssinaturaCertaEErradaPorHTTP(t *testing.T) {
	srv := httptest.NewServer(novoServico(chavesDeTeste()).rotas())
	defer srv.Close()
	for _, versao := range []string{"v1", "v2"} {
		_, c := emitirPorHTTP(t, srv, versao, "Ana Souza", 100)
		for assinatura, esperado := range map[string]bool{c.Assinatura: true, strings.Repeat("00", 32): false} {
			corpo, _ := json.Marshal(map[string]string{"assinatura": assinatura})
			resp, err := http.Post(srv.URL+"/"+versao+"/comprovantes/"+c.ID+"/conferir", "application/json", bytes.NewReader(corpo))
			if err != nil {
				t.Fatal(err)
			}
			var r map[string]bool
			_ = json.NewDecoder(resp.Body).Decode(&r)
			resp.Body.Close()
			if r["valido"] != esperado {
				t.Errorf("%s: assinatura %s... valido=%v", versao, assinatura[:8], r["valido"])
			}
		}
	}
}

// BRECHA-012. 2^32 + 100 centavos são R$ 42.949.673,96. Convertido para
// int32, vira 100, e a transferência passa sem segunda aprovação.
func TestBrecha012ValorEstouraOInt32EPulaAAprovacao(t *testing.T) {
	srv := httptest.NewServer(novoServico(chavesDeTeste()).rotas())
	defer srv.Close()

	status, c := emitirPorHTTP(t, srv, "v1", "Ana Souza", 1<<32+100)
	if status != http.StatusCreated || c.PrecisaAprovar {
		t.Fatalf("esperava o v1 aceitar R$ 42 milhões sem aprovação: status %d, precisaAprovar %v", status, c.PrecisaAprovar)
	}
}

func TestBrecha012V2CompararEmInt64ERecusaValorForaDaFaixa(t *testing.T) {
	srv := httptest.NewServer(novoServico(chavesDeTeste()).rotas())
	defer srv.Close()

	for _, valor := range []int64{1<<32 + 100, 0, -500} {
		if status, _ := emitirPorHTTP(t, srv, "v2", "Ana Souza", valor); status != http.StatusBadRequest {
			t.Errorf("v2 aceitou valor %d: status %d", valor, status)
		}
	}
	if _, c := emitirPorHTTP(t, srv, "v2", "Ana Souza", LimiteSemAprovacao+1); !c.PrecisaAprovar {
		t.Error("v2 deixou passar sem aprovação um valor acima do limite")
	}
	if _, c := emitirPorHTTP(t, srv, "v2", "Ana Souza", LimiteSemAprovacao); c.PrecisaAprovar {
		t.Error("v2 pediu aprovação para o valor exatamente no limite")
	}
}

func TestEntradaInvalidaERecusadaNasDuasVersoes(t *testing.T) {
	srv := httptest.NewServer(novoServico(chavesDeTeste()).rotas())
	defer srv.Close()
	for _, versao := range []string{"v1", "v2"} {
		for _, corpo := range []string{`{`, `{"destino":"x","pagador":"y","valorCentavos":1,"extra":1}`, `{"pagador":"y","valorCentavos":1}`,
			`{"destino":"x","pagador":"` + strings.Repeat("a", 5000) + `","valorCentavos":1}`} {
			resp, err := http.Post(srv.URL+"/"+versao+"/comprovantes", "application/json", strings.NewReader(corpo))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s aceitou %.30q: %d", versao, corpo, resp.StatusCode)
			}
		}
	}
}
