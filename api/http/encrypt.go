package http

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
)

func EncryptHandler(key []byte) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}

		encryptedMsg, err := encrypt(key, body)
		if err != nil {
			http.Error(w, "failed to encrypt body", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "encrypted body %s\n", base64.URLEncoding.EncodeToString(encryptedMsg))
	}
}

func encrypt(key, input []byte) ([]byte, error) {
	bCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher while encrypting: %w", err)
	}
	log.Println(string(input))

	buf := new(bytes.Buffer)
	s := cipher.NewCTR(bCipher, make([]byte, aes.BlockSize))
	streamW := &cipher.StreamWriter{
		S: s,
		W: buf,
	}

	_, err = streamW.Write(input)
	if err != nil {
		return nil, fmt.Errorf("writing to encrypt stream: %v", err)
	}

	log.Println(buf.String())

	return buf.Bytes(), nil
}
