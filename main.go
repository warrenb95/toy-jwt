package main

import (
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	apihttp "github.com/warrenb95/toy-jwt/api/http"
	"github.com/warrenb95/toy-jwt/internal/generator"
)

var (
	secretKey = "super secret key ;)"
)

func main() {
	keys := make(map[string]generator.Key)
	err := generator.Generate(keys)
	if err != nil {
		log.Fatalf("failed to generate key: %v", err)
	}

	go func() {
		ticker := time.NewTicker(time.Hour * 12)
		for {
			<-ticker.C
			err := generator.Generate(keys)
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
	mux.HandleFunc("/", apihttp.CreateToken(keys))
	mux.HandleFunc("/parse-token", apihttp.ParseToken(keys))
	mux.HandleFunc("/encrypt", apihttp.EncryptHandler(myCipherKey))
	mux.HandleFunc("/decrypt", apihttp.DecryptHandler(myCipherKey))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
