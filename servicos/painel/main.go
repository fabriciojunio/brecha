// Painel de operação do brecha: só na rede interna, e por isso, no
// laboratório, sem senha. A rota /config mostra a configuração "para o time
// conferir" e, com ela, os segredos que estão em variável de ambiente. É o
// alvo da pós-exploração do relatório. Dados simulados.
//
// Na versão corrigida (PAINEL_TOKEN_ARQUIVO definido), toda rota exige o token
// do painel e a /config deixa de existir: segredo não se mostra, nem para
// quem é de dentro.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Prefixos das variáveis que a /config do laboratório expõe.
var prefixos = []string{"BRECHA_", "PG", "COMPROVANTES_", "RELATORIOS_", "DJANGO_"}

func configuracao() map[string]string {
	saida := map[string]string{}
	for _, par := range os.Environ() {
		nome, valor, _ := strings.Cut(par, "=")
		for _, prefixo := range prefixos {
			if strings.HasPrefix(nome, prefixo) {
				saida[nome] = valor
			}
		}
	}
	return saida
}

func rotas(token []byte) http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /saude", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("Painel de operação do brecha (dados simulados)\n"))
	})
	if token == nil {
		m.HandleFunc("GET /config", func(w http.ResponseWriter, _ *http.Request) {
			nomes := []string{}
			cfg := configuracao()
			for nome := range cfg {
				nomes = append(nomes, nome)
			}
			sort.Strings(nomes)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"variaveis": nomes, "valores": cfg})
		})
		return m
	}
	return exigirToken(token, m)
}

func exigirToken(token []byte, proximo http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/saude" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Token-Painel")), token) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		proximo.ServeHTTP(w, r)
	})
}

func main() {
	var token []byte
	if arquivo := os.Getenv("PAINEL_TOKEN_ARQUIVO"); arquivo != "" {
		// #nosec G304 -- caminho do segredo definido por quem sobe o serviço.
		bruto, err := os.ReadFile(filepath.Clean(arquivo))
		if err != nil || len(strings.TrimSpace(string(bruto))) < 32 {
			slog.Error("token do painel ausente ou curto")
			os.Exit(1)
		}
		token = []byte(strings.TrimSpace(string(bruto)))
	}
	servidor := &http.Server{
		Addr:              ":8080",
		Handler:           rotas(token),
		ReadHeaderTimeout: 5 * time.Second,
	}
	slog.Info("painel no ar", "protegido", token != nil)
	if err := servidor.ListenAndServe(); err != nil {
		slog.Error("painel parou", "erro", err)
		os.Exit(1)
	}
}
