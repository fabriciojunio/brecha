// Serviço de comprovantes do brecha.
//
// Emite o comprovante de uma transferência: os dados do pagador vão cifrados
// (só o banco lê), e a assinatura deixa qualquer um conferir que o comprovante
// é verdadeiro. Transferência acima do limite precisa de segunda aprovação.
//
// O /v1 tem três falhas plantadas, todas de Go e de criptografia; o /v2 é a
// mesma coisa corrigida. Dados simulados.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// LimiteSemAprovacao é o valor, em centavos, acima do qual a transferência
// precisa de segunda aprovação: R$ 10.000,00.
const LimiteSemAprovacao int64 = 1_000_000

// ValorMaximo é o maior valor aceito numa transferência: R$ 1.000.000,00.
const ValorMaximo int64 = 100_000_000

var ErrValorInvalido = errors.New("valor inválido")

// Chaves do serviço. A de cifra protege o sigilo do pagador; a de assinatura,
// a autenticidade. Chave separada para cada uso: vazar uma não entrega a outra.
type Chaves struct {
	Cifra      []byte // 32 bytes, AES-256
	Assinatura []byte // 32 bytes, HMAC-SHA256
}

// Comprovante é o que o cliente recebe.
type Comprovante struct {
	ID             string `json:"id"`
	Destino        string `json:"destino"`
	ValorCentavos  int64  `json:"valorCentavos"`
	PagadorCifrado string `json:"pagadorCifrado"`
	Assinatura     string `json:"assinatura"`
	PrecisaAprovar bool   `json:"precisaAprovar"`
}

func (c Comprovante) mensagem() []byte {
	return []byte(fmt.Sprintf("%s|%s|%d|%s", c.ID, c.Destino, c.ValorCentavos, c.PagadorCifrado))
}

// --- v1: como chega a produção quando ninguém revisa ---------------------------

// nonceFixo é o erro do BRECHA-010: o mesmo nonce em todo comprovante. No GCM,
// repetir o nonce com a mesma chave repete o fluxo de cifra, e o XOR de dois
// textos cifrados vira o XOR dos dois textos claros.
var nonceFixo = make([]byte, 12)

func cifrarV1(chave []byte, texto string) (string, error) {
	gcm, err := novoGCM(chave)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(gcm.Seal(nil, nonceFixo, []byte(texto), nil)), nil
}

// assinaturaConfereV1 é o erro do BRECHA-011: compara byte a byte e para no
// primeiro diferente. Quanto mais bytes certos, mais demora a resposta, e quem
// mede o tempo descobre a assinatura byte por byte.
func assinaturaConfereV1(chave []byte, c Comprovante, recebida []byte) bool {
	return compararV1(recebida, assinar(chave, c))
}

func compararV1(recebida, esperada []byte) bool {
	if len(recebida) != len(esperada) {
		return false
	}
	for i := range esperada {
		if recebida[i] != esperada[i] {
			return false
		}
	}
	return true
}

// precisaAprovarV1 é o erro do BRECHA-012: o valor chega em int64 e é
// convertido para int32 antes da comparação. Go não acusa estouro na
// conversão; 4.294.967.396 centavos viram 100 e passam sem aprovação.
func precisaAprovarV1(valor int64) bool {
	return int32(valor) > int32(LimiteSemAprovacao)
}

func EmitirV1(chaves Chaves, id, destino, pagador string, valor int64) (Comprovante, error) {
	cifrado, err := cifrarV1(chaves.Cifra, pagador)
	if err != nil {
		return Comprovante{}, err
	}
	c := Comprovante{ID: id, Destino: destino, ValorCentavos: valor, PagadorCifrado: cifrado,
		PrecisaAprovar: precisaAprovarV1(valor)}
	c.Assinatura = hex.EncodeToString(assinar(chaves.Assinatura, c))
	return c, nil
}

// --- v2: corrigido --------------------------------------------------------------

func cifrarV2(chave []byte, texto string) (string, error) {
	gcm, err := novoGCM(chave)
	if err != nil {
		return "", err
	}
	// Nonce aleatório de 96 bits por comprovante, gravado na frente do texto
	// cifrado. Com a mesma chave, a chance de repetir só fica relevante perto
	// de 2^32 comprovantes; antes disso a chave tem de ser trocada.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(gcm.Seal(nonce, nonce, []byte(texto), nil)), nil
}

// DecifrarV2 devolve o pagador de um comprovante emitido pelo /v2.
func DecifrarV2(chave []byte, cifrado string) (string, error) {
	bruto, err := hex.DecodeString(cifrado)
	if err != nil {
		return "", err
	}
	gcm, err := novoGCM(chave)
	if err != nil {
		return "", err
	}
	if len(bruto) < gcm.NonceSize() {
		return "", errors.New("comprovante cifrado curto demais")
	}
	texto, err := gcm.Open(nil, bruto[:gcm.NonceSize()], bruto[gcm.NonceSize():], nil)
	return string(texto), err
}

func assinaturaConfereV2(chave []byte, c Comprovante, recebida []byte) bool {
	// Tempo constante: a comparação leva o mesmo tempo, acerte o atacante um
	// byte ou todos.
	return hmac.Equal(recebida, assinar(chave, c))
}

func precisaAprovarV2(valor int64) (bool, error) {
	if valor <= 0 || valor > ValorMaximo {
		return false, ErrValorInvalido
	}
	return valor > LimiteSemAprovacao, nil
}

func EmitirV2(chaves Chaves, id, destino, pagador string, valor int64) (Comprovante, error) {
	aprovar, err := precisaAprovarV2(valor)
	if err != nil {
		return Comprovante{}, err
	}
	cifrado, err := cifrarV2(chaves.Cifra, pagador)
	if err != nil {
		return Comprovante{}, err
	}
	c := Comprovante{ID: id, Destino: destino, ValorCentavos: valor, PagadorCifrado: cifrado, PrecisaAprovar: aprovar}
	c.Assinatura = hex.EncodeToString(assinar(chaves.Assinatura, c))
	return c, nil
}

// --- comum ----------------------------------------------------------------------

func novoGCM(chave []byte) (cipher.AEAD, error) {
	bloco, err := aes.NewCipher(chave)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(bloco)
}

func assinar(chave []byte, c Comprovante) []byte {
	mac := hmac.New(sha256.New, chave)
	mac.Write(c.mensagem())
	return mac.Sum(nil)
}
