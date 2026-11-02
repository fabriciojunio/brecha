package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const tamanhoMaximoDoCorpo = 4 << 10

type servico struct {
	chaves      Chaves
	mu          sync.Mutex
	comprovante map[string]Comprovante
	sequencia   int
}

type pedido struct {
	Destino       string `json:"destino"`
	Pagador       string `json:"pagador"`
	ValorCentavos int64  `json:"valorCentavos"`
}

func novoServico(chaves Chaves) *servico {
	return &servico{chaves: chaves, comprovante: map[string]Comprovante{}}
}

func (s *servico) rotas() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/comprovantes", s.emitir(EmitirV1))
	m.HandleFunc("POST /v2/comprovantes", s.emitir(EmitirV2))
	// O comprovante é público pelo id, como um link que o pagador manda para
	// quem recebeu. Por isso o dado do pagador vai cifrado.
	m.HandleFunc("GET /v1/comprovantes/{id}", s.consultar)
	m.HandleFunc("GET /v2/comprovantes/{id}", s.consultar)
	m.HandleFunc("POST /v1/comprovantes/{id}/conferir", s.conferir(assinaturaConfereV1))
	m.HandleFunc("POST /v2/comprovantes/{id}/conferir", s.conferir(assinaturaConfereV2))
	m.HandleFunc("GET /saude", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return m
}

func (s *servico) emitir(emitir func(Chaves, string, string, string, int64) (Comprovante, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p pedido
		if !lerJSON(w, r, &p) {
			return
		}
		if p.Destino == "" || p.Pagador == "" || len(p.Destino) > 64 || len(p.Pagador) > 128 {
			responder(w, http.StatusBadRequest, map[string]string{"erro": "destino e pagador são obrigatórios"})
			return
		}
		s.mu.Lock()
		s.sequencia++
		id := fmt.Sprintf("c%06d", s.sequencia)
		s.mu.Unlock()

		c, err := emitir(s.chaves, id, p.Destino, p.Pagador, p.ValorCentavos)
		if errors.Is(err, ErrValorInvalido) {
			responder(w, http.StatusBadRequest, map[string]string{"erro": "valor inválido"})
			return
		}
		if err != nil {
			slog.Error("falha ao emitir comprovante", "erro", err)
			responder(w, http.StatusInternalServerError, map[string]string{"erro": "erro interno"})
			return
		}
		s.mu.Lock()
		s.comprovante[id] = c
		s.mu.Unlock()
		responder(w, http.StatusCreated, c)
	}
}

func (s *servico) buscar(id string) (Comprovante, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.comprovante[id]
	return c, ok
}

func (s *servico) consultar(w http.ResponseWriter, r *http.Request) {
	c, ok := s.buscar(r.PathValue("id"))
	if !ok {
		responder(w, http.StatusNotFound, map[string]string{"erro": "comprovante não encontrado"})
		return
	}
	responder(w, http.StatusOK, c)
}

func (s *servico) conferir(confere func([]byte, Comprovante, []byte) bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.buscar(r.PathValue("id"))
		if !ok {
			responder(w, http.StatusNotFound, map[string]string{"erro": "comprovante não encontrado"})
			return
		}
		var corpo struct {
			Assinatura string `json:"assinatura"`
		}
		if !lerJSON(w, r, &corpo) {
			return
		}
		recebida, err := hex.DecodeString(corpo.Assinatura)
		if err != nil {
			responder(w, http.StatusBadRequest, map[string]string{"erro": "assinatura em hexadecimal"})
			return
		}
		responder(w, http.StatusOK, map[string]bool{"valido": confere(s.chaves.Assinatura, c, recebida)})
	}
}

func lerJSON(w http.ResponseWriter, r *http.Request, destino any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, tamanhoMaximoDoCorpo))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destino); err != nil {
		responder(w, http.StatusBadRequest, map[string]string{"erro": "JSON inválido"})
		return false
	}
	return true
}

func responder(w http.ResponseWriter, status int, corpo any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(corpo); err != nil {
		slog.Error("falha ao escrever a resposta", "erro", err)
	}
}

// carregarChaves lê as chaves de arquivos de segredo (COMPROVANTES_SEGREDOS,
// um diretório com cifra.hex e assinatura.hex). Variável de ambiente só no
// laboratório, com COMPROVANTES_CHAVE_CIFRA e COMPROVANTES_CHAVE_ASSINATURA:
// é a configuração que a pós-exploração do relatório encontra.
func carregarChaves() (Chaves, error) {
	ler := func(arquivo, variavel string) ([]byte, error) {
		texto := os.Getenv(variavel)
		if dir := os.Getenv("COMPROVANTES_SEGREDOS"); dir != "" {
			// #nosec G304 -- o diretório vem da configuração de quem sobe o
			// serviço, e o nome do arquivo é fixo neste código.
			bruto, err := os.ReadFile(filepath.Join(filepath.Clean(dir), arquivo))
			if err != nil {
				return nil, err
			}
			texto = string(bruto)
		}
		chave, err := hex.DecodeString(strings.TrimSpace(texto))
		if err != nil || len(chave) != 32 {
			return nil, fmt.Errorf("%s: chave de 32 bytes em hexadecimal", arquivo)
		}
		return chave, nil
	}
	cifra, err := ler("cifra.hex", "COMPROVANTES_CHAVE_CIFRA")
	if err != nil {
		return Chaves{}, err
	}
	assinatura, err := ler("assinatura.hex", "COMPROVANTES_CHAVE_ASSINATURA")
	if err != nil {
		return Chaves{}, err
	}
	return Chaves{Cifra: cifra, Assinatura: assinatura}, nil
}

func main() {
	chaves, err := carregarChaves()
	if err != nil {
		slog.Error("chaves ausentes", "erro", err)
		os.Exit(1)
	}
	endereco := os.Getenv("COMPROVANTES_ENDERECO")
	if endereco == "" {
		// Vulnerável de propósito: por padrão, só nesta máquina.
		endereco = "127.0.0.1:8090"
	}
	servidor := &http.Server{
		Addr:              endereco,
		Handler:           novoServico(chaves).rotas(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	slog.Info("comprovantes no ar", "endereco", endereco)
	if err := servidor.ListenAndServe(); err != nil {
		slog.Error("servidor parou", "erro", err)
		os.Exit(1)
	}
}
