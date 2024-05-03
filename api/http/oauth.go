package http

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

// TODO: user session store

type state int

const (
	none = state(iota)
	requested
	created
	expired
)

type session struct {
	token      string
	expiration time.Time
	state      state
}

// sessions user session_id to expiration map
var sessions map[string]session

var conf = &oauth2.Config{
	ClientID:     os.Getenv("GIT_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GIT_OAUTH_CLIENT_SECRET"),
	Endpoint:     github.Endpoint,
}

func SignupHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.NewString()
	if sessions == nil {
		sessions = make(map[string]session)
	}
	sessions[sessionID] = session{
		state: requested,
	}

	url := conf.AuthCodeURL(sessionID)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func AuthCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: get the 'code' param
	code := r.Form.Get("code")
	if code == "" {
		log.Fatal("Failed to get code from callback query params")
	}

	log.Println("code: ", code)

	tok, err := conf.Exchange(context.Background(), code)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("token: %s\n", tok.AccessToken)
}
