package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	currentKeyID = ""
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

func createToken(keys map[string]key) func(w http.ResponseWriter, r *http.Request) {
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

func parseToken(keys map[string]key) func(w http.ResponseWriter, r *http.Request) {
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", createToken(keys))
	mux.HandleFunc("/parse-token", parseToken(keys))

	log.Fatal(http.ListenAndServe(":8080", mux))
}