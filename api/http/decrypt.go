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

func DecryptHandler(key []byte) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
		}
		if err := r.Body.Close(); err != nil {
			log.Println(err.Error())
		}

		body, err = base64.URLEncoding.DecodeString(string(body))
		if err != nil {
			http.Error(w, "failed to decode body", http.StatusInternalServerError)
			return
		}

		decryptedMsg, err := decrypt(key, body)
		if err != nil {
			http.Error(w, "failed to decrypt body", http.StatusInternalServerError)
			return
		}

		fmt.Fprintf(w, "decrypted body %s\n", decryptedMsg)
	}
}

func decrypt(key, encryptedInput []byte) ([]byte, error) {
	bCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("creating cipher while decrypting: %w", err)
	}
	log.Println(string(encryptedInput))

	inBuffer := bytes.NewReader(encryptedInput)
	s := cipher.NewCTR(bCipher, make([]byte, aes.BlockSize))
	streamR := &cipher.StreamReader{
		S: s,
		R: inBuffer,
	}

	decryptedBuffer := make([]byte, len(encryptedInput))
	_, err = streamR.Read(decryptedBuffer)
	if err != nil {
		return nil, fmt.Errorf("reading into out buffer: %v", err)
	}

	log.Println(string(decryptedBuffer))

	return decryptedBuffer, nil
}
