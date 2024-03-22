package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var (
	currentKeyID = ""
	secretKey    = "super secret key ;)"
)

type key struct {
	value     []byte
	createdAt time.Time
}

type userClaims struct {
	jwt.RegisteredClaims
	SessionID string
}

func (u *userClaims) Validate() error {
	if u.SessionID == "" {
		return errors.New("empty session ID in token")
	}

	return nil
}

func createToken(keys map[string]key) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, userClaims{
			SessionID: fmt.Sprintf("Your Session ID: %s", time.Now().String()),
		})
		token.Header["kid"] = currentKeyID

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(keys[currentKeyID].value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		fmt.Fprintf(w, "%s\n", tokenString)
	}
}

func parseToken(keys map[string]key) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		jwtToken := r.Header.Get("authorization")

		t, err := jwt.ParseWithClaims(jwtToken, &userClaims{}, func(t *jwt.Token) (interface{}, error) {
			if t.Method.Alg() != jwt.SigningMethodHS512.Alg() {
				return nil, errors.New("invalid signing algorithm")
			}

			kID, ok := t.Header["kid"].(string)
			if !ok {
				return nil, errors.New("Invalid Key ID")
			}

			key, ok := keys[kID]
			if !ok {
				return nil, errors.New("Invalid Key ID")
			}

			return key.value, nil
		})
		if err != nil {
			http.Error(w, fmt.Errorf("failed to parse token: %w", err).Error(), http.StatusInternalServerError)
			return
		}

		if !t.Valid {
			http.Error(w, "token is invalid", http.StatusInternalServerError)
			return
		}

		claims := t.Claims.(*userClaims)
		fmt.Fprintf(w, "user session ID: %s", claims.SessionID)
	}
}

func generateKey(keys map[string]key) error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("failed to read random bytes into new key while generating key: %w", err)
	}

	keyUUID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("failed to create key UUID while generating key: %w", err)
	}

	keys[keyUUID.String()] = key{
		value:     newKey,
		createdAt: time.Now().UTC(),
	}
	currentKeyID = keyUUID.String()
	log.Printf("current key ID: %s", currentKeyID)

	return nil
}

func encryptHandler(key []byte) func(http.ResponseWriter, *http.Request) {
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

func decryptHandler(key []byte) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "failed to read body", http.StatusInternalServerError)
			return
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

func main() {
	keys := make(map[string]key)
	err := generateKey(keys)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	go func() {
		ticker := time.NewTicker(time.Hour * 12)
		for {
			<-ticker.C
			err := generateKey(keys)
			if err != nil {
				log.Fatalf("failed to generate key: %v", err)
			}
		}
	}()

	myCipherKey, err := bcrypt.GenerateFromPassword([]byte(secretKey), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}
	myCipherKey = myCipherKey[:16] // Only need 16 bytes

	mux := http.NewServeMux()
	mux.HandleFunc("/", createToken(keys))
	mux.HandleFunc("/parse-token", parseToken(keys))
	mux.HandleFunc("/encrypt", encryptHandler(myCipherKey))
	mux.HandleFunc("/decrypt", decryptHandler(myCipherKey))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
