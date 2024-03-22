package generator

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/google/uuid"
)

var currentKeyID = ""

type Key struct {
	Value     []byte
	CreatedAt time.Time
}

func Generate(keys map[string]Key) error {
	newKey := make([]byte, 64)
	_, err := io.ReadFull(rand.Reader, newKey)
	if err != nil {
		return fmt.Errorf("failed to read random bytes into new key while generating key: %w", err)
	}

	keyUUID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("failed to create key UUID while generating key: %w", err)
	}

	keys[keyUUID.String()] = Key{
		Value:     newKey,
		CreatedAt: time.Now().UTC(),
	}
	currentKeyID = keyUUID.String()
	log.Printf("current key ID: %s", currentKeyID)

	return nil
}

func CurrentKeyID() string {
	return currentKeyID
}
