package main

import (
	"chirpy/internal/auth"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
)

func (cfg *apiConfig) UpgradeUser(w http.ResponseWriter, r *http.Request) {

	ApiKey, err := auth.GetAPIKey(r.Header)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	if ApiKey != cfg.polkaKey {
		w.WriteHeader(401)
		return
	}

	//define the struct we would need to Unmarshal from the body

	type RequestBody struct {
		Event string `json:"event"`
		Data  struct {
			UserID string `json:"user_id"`
		} `json:"data"`
	}

	//decode the request body
	reqBody := RequestBody{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&reqBody)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if reqBody.Event != "user.upgraded" {
		w.WriteHeader(http.StatusNoContent)
		return
	} else if reqBody.Event == "user.upgraded" {

		parsedID, err := uuid.Parse(reqBody.Data.UserID)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		_, err = cfg.db.UpgradeToChirpyRed(r.Context(), parsedID)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.WriteHeader(204)
		return

	}

}
