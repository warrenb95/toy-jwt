package http

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/warrenb95/toy-jwt/internal/generator"
)

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

func CreateToken(keys map[string]generator.Key) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS512, userClaims{
			SessionID: fmt.Sprintf("Your Session ID: %s", time.Now().String()),
		})
		token.Header["kid"] = generator.CurrentKeyID()

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString(keys[generator.CurrentKeyID()].Value)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		fmt.Fprintf(w, "%s\n", tokenString)
	}
}

func ParseToken(keys map[string]generator.Key) func(http.ResponseWriter, *http.Request) {
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

			return key.Value, nil
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
