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

type loginState int

const (
	none = loginState(iota)
	requested
	codeRequested
	tokenRequested
	created
	expired
)

type session struct {
	token      string
	expiration time.Time
	state      loginState
}

// sessions user session_id to expiration map
var sessions map[string]*session

var conf = &oauth2.Config{
	ClientID:     os.Getenv("GIT_OAUTH_CLIENT_ID"),
	ClientSecret: os.Getenv("GIT_OAUTH_CLIENT_SECRET"),
	Endpoint:     github.Endpoint,
	// RedirectURL:  "http://127.0.0.1/oauth2/receive",
}

func GithubOAuth2Handler(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.NewString()
	if sessions == nil {
		sessions = make(map[string]*session)
	}
	sessions[sessionID] = &session{
		state: requested,
	}

	url := conf.AuthCodeURL(sessionID)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func OAuth2Reveive(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()

	code := queryParams.Get("code")
	if code == "" {
		log.Fatal("Failed to get code from callback query params")
	}
	log.Println("code: ", code)

	// TODO: validate the state query param
	state := queryParams.Get("state")
	if _, ok := sessions[state]; ok {
		log.Println("session found: ", state)
		sessions[state] = &session{
			state: codeRequested,
		}
	} else {
		return
	}

	tok, err := conf.Exchange(context.Background(), code)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("token: %s\n", tok.AccessToken)
}
