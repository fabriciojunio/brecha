package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLaboratorioMostraOsSegredosNaConfig(t *testing.T) {
	t.Setenv("BRECHA_SEGREDO", "segredo-de-teste-com-mais-de-32-bytes-ok")
	t.Setenv("HOME", "/root")
	rec := httptest.NewRecorder()
	rotas(nil).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "segredo-de-teste") {
		t.Fatalf("esperava a /config aberta com o segredo: %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "/root") {
		t.Fatal("a /config só expõe as variáveis da aplicação")
	}
}

func TestCorrigidoExigeTokenENaoTemConfig(t *testing.T) {
	t.Setenv("BRECHA_SEGREDO", "segredo-de-teste-com-mais-de-32-bytes-ok")
	token := []byte(strings.Repeat("t", 40))
	h := rotas(token)

	semToken := httptest.NewRecorder()
	h.ServeHTTP(semToken, httptest.NewRequest(http.MethodGet, "/", nil))
	if semToken.Code != http.StatusUnauthorized {
		t.Fatalf("sem token: %d", semToken.Code)
	}

	pedido := httptest.NewRequest(http.MethodGet, "/config", nil)
	pedido.Header.Set("X-Token-Painel", string(token))
	comToken := httptest.NewRecorder()
	h.ServeHTTP(comToken, pedido)
	if comToken.Code != http.StatusNotFound || strings.Contains(comToken.Body.String(), "segredo") {
		t.Fatalf("a /config não pode existir na versão corrigida: %d %s", comToken.Code, comToken.Body)
	}

	saude := httptest.NewRecorder()
	h.ServeHTTP(saude, httptest.NewRequest(http.MethodGet, "/saude", nil))
	if saude.Code != http.StatusNoContent {
		t.Fatalf("a saúde fica aberta para o orquestrador: %d", saude.Code)
	}
}
