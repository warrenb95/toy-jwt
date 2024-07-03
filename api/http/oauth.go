package http

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
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

type loginSession struct {
	token      string
	expiration time.Time
	state      loginState
}

var (
	// logins user session_id to expiration map
	logins map[string]*loginSession

	githubGraphQLURL = "https://api.github.com/graphql"

	conf = &oauth2.Config{
		ClientID:     os.Getenv("GIT_OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("GIT_OAUTH_CLIENT_SECRET"),
		Endpoint:     github.Endpoint,
		// RedirectURL:  "http://127.0.0.1/oauth2/receive",
	}
)

func GithubOAuth2Handler(w http.ResponseWriter, r *http.Request) {
	sessionID := uuid.NewString()
	if logins == nil {
		logins = make(map[string]*loginSession)
	}
	logins[sessionID] = &loginSession{
		state: requested,
	}

	url := conf.AuthCodeURL(sessionID)
	http.Redirect(w, r, url, http.StatusSeeOther)
}

func OAuth2Receive(w http.ResponseWriter, r *http.Request) {
	queryParams := r.URL.Query()

	code := queryParams.Get("code")
	if code == "" {
		log.Fatal("Failed to get code from callback query params")
	}
	log.Println("code: ", code)

	// TODO: validate the state query param
	state := queryParams.Get("state")
	if _, ok := logins[state]; ok {
		log.Println("session found: ", state)
		logins[state] = &loginSession{
			state: codeRequested,
		}
	} else {
		return
	}

	tok, err := conf.Exchange(r.Context(), code)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("token: %s\n", tok.AccessToken)

	ts := conf.TokenSource(r.Context(), tok)

	client := oauth2.NewClient(r.Context(), ts)
	requestBody := strings.NewReader(`{"query": "query {viewer {id}}"}`)
	response, err := client.Post(githubGraphQLURL, "application/json", requestBody)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()

	respBytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(w, "OAuth client created\ngithubGraphQLURL response body: %s", respBytes)
}
