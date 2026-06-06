package main

import (
	"chirpy/internal/auth"
	"chirpy/internal/database"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// struct for holding stateful in memory data
type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	platform       string
	jwtSecret      string
	polkaKey       string
}

// user struct mapped to database

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	JWT          string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
	IsChirpyRed  bool      `json:"is_chirpy_red"`
}

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string    `json:"body"`
	UserID    uuid.UUID `json:"user_id"`
}

//middleware that increments fileserverHits

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})

}

func (cfg *apiConfig) hitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body := fmt.Sprintf("<html>\n  <body>\n    <h1>Welcome, Chirpy Admin</h1>\n    <p>Chirpy has been visited %d times!</p>\n  </body>\n</html>", cfg.fileserverHits.Load())
	_, err := w.Write([]byte(body))
	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}
}

func (cfg *apiConfig) resetHits(w http.ResponseWriter, r *http.Request) {

	//cfg.fileserverHits.Store(0)
	//healthHandler(w, r)

	//above code shows the previous implementation

	if cfg.platform != "dev" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	err := cfg.db.DeleteAllUsers(r.Context())

	if err != nil {
		fmt.Println("Error: Something went wrong")
		w.WriteHeader(500)
	}

	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) createUser(w http.ResponseWriter, r *http.Request) {

	type UserParams struct {
		Email          string `json:"email"`
		HashedPassword string `json:"password"`
	}

	// lets decode the request body to get the email
	userStruct := User{}
	params := UserParams{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	// hashing the password here before storing it in the database
	hashedPassword, err := auth.HashPassword(params.HashedPassword)

	if err != nil {
		fmt.Printf("Error, Unable to hash password: %s\n", err)
		w.WriteHeader(500)
		return
	}

	createParams := database.CreateUserParams{
		Email:          params.Email,
		HashedPassword: hashedPassword,
	}

	user, err := cfg.db.CreateUser(r.Context(), createParams)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	userStruct = User{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	body, err := json.Marshal(userStruct)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	w.Write(body)

}

func (cfg *apiConfig) getUser(w http.ResponseWriter, r *http.Request) {

	//decode the request body
	type UserParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	params := UserParams{}
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&params)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	// check if user exists in the database
	user, err := cfg.db.GetUserByEmail(r.Context(), params.Email)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}

	//Now check if the password is correct
	match, err := auth.CheckPasswordHash(params.Password, user.HashedPassword)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		w.Write([]byte("Incorrect email or password"))
		return
	}

	if match == false {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte("Incorrect email or password"))
	} else {

		// Do I need to create the logic for JWT here? (logic removed)

		// the jwt should just always expire after one hour
		jwtExpiresIn := time.Hour

		// now we make a jwt

		jwt, err := auth.MakeJWT(user.ID, cfg.jwtSecret, jwtExpiresIn)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}

		// now we also get a refresh token
		myRefreshToken := auth.MakeRefreshToken()

		//store the token in the database
		tokenInfo, err := cfg.db.CreateUserToken(r.Context(), database.CreateUserTokenParams{
			UserID:    user.ID,
			Token:     myRefreshToken,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 60),
		})

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}

		userStruct := User{
			ID:           user.ID,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			Email:        user.Email,
			JWT:          jwt,
			RefreshToken: tokenInfo.Token,
			IsChirpyRed:  user.IsChirpyRed,
		}

		body, err := json.Marshal(userStruct)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write(body)
	}

}

func (cfg *apiConfig) updateUser(w http.ResponseWriter, r *http.Request) {

	type UserParams struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	type ResponseUser struct {
		ID          uuid.UUID `json:"id"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
		Email       string    `json:"email"`
		IsChirpyRed bool      `json:"is_chirpy_red"`
	}

	// first we need to access the token in the header

	jwt, err := auth.GetBearerToken(r.Header)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	//now verify that the token is still active and not revoked or expired

	jwtUserID, err := auth.ValidateJWT(jwt, cfg.jwtSecret)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	params := UserParams{}
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&params)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	hashedPassword, err := auth.HashPassword(params.Password)

	if err != nil {
		fmt.Printf("Error, Unable to hash password: %s\n", err)
		w.WriteHeader(500)
		return
	}

	user, err := cfg.db.UpdateUser(r.Context(), database.UpdateUserParams{ID: jwtUserID, Email: params.Email, HashedPassword: hashedPassword})

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	responseUser := ResponseUser{
		ID:          user.ID,
		CreatedAt:   user.CreatedAt,
		UpdatedAt:   user.UpdatedAt,
		Email:       user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	body, err := json.Marshal(responseUser)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (cfg *apiConfig) createChirps(w http.ResponseWriter, r *http.Request) {

	//extract the token from header
	token, err := auth.GetBearerToken(r.Header)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	//validate the token
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	type UserChirp struct {
		UserID uuid.UUID `json:"user_id"`
		Body   string    `json:"body"`
	}

	thisChirp := Chirp{}
	params := UserChirp{}

	decoder := json.NewDecoder(r.Body)

	err = decoder.Decode(&params)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	if len(params.Body) > 140 {
		w.WriteHeader(http.StatusBadRequest)
		return
	} else {

		bannedWords := []string{"kerfuffle", "sharbert", "fornax"}
		words := strings.Split(params.Body, " ")
		for i := 0; i < len(words); i++ {
			for j := 0; j < len(bannedWords); j++ {
				if strings.ToLower(words[i]) == bannedWords[j] {
					words[i] = "****"
				}
			}
		}
		cleanChirp := strings.Join(words, " ")

		chirp, err := cfg.db.CreateChirp(r.Context(), database.CreateChirpParams{Body: cleanChirp, UserID: userID})

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}

		thisChirp = Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      cleanChirp,
			UserID:    chirp.UserID,
		}

		body, err := json.Marshal(thisChirp)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		w.Write(body)
		return

	}

}

func (cfg *apiConfig) getChirps(w http.ResponseWriter, r *http.Request) {

	userID := r.URL.Query().Get("author_id")
	var chirps []database.Chirp

	if userID != "" {
		parsedID, err := uuid.Parse(userID)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		chirps, err = cfg.db.GetChirpsByUser(r.Context(), parsedID)

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}

	} else {
		// get all chirps from DB
		var err error
		chirps, err = cfg.db.GetChirps(r.Context())

		if err != nil {
			fmt.Printf("Error: %s\n", err)
			w.WriteHeader(500)
			return
		}
	}

	allChirps := []Chirp{}

	for _, chirp := range chirps {
		allChirps = append(allChirps, Chirp{
			ID:        chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body:      chirp.Body,
			UserID:    chirp.UserID,
		})
	}

	// here we can check and sort the chirps
	sortQuery := r.URL.Query().Get("sort")

	if sortQuery == "desc" {
		sort.Slice(allChirps, func(i, j int) bool {
			return allChirps[i].CreatedAt.After(allChirps[j].CreatedAt)
		})
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body, err := json.Marshal(allChirps)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}

	w.Write(body)
	return
}

func (cfg *apiConfig) getChirpsById(w http.ResponseWriter, r *http.Request) {

	chirpID, err := uuid.Parse(r.PathValue("chirpID"))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return

	}

	chirp, err := cfg.db.GetChirpsById(r.Context(), chirpID)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(404)
		return
	}

	returnChirp := Chirp{
		ID:        chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body:      chirp.Body,
		UserID:    chirp.UserID,
	}

	body, err := json.Marshal(returnChirp)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(404)
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
	return

}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	body := "OK"

	_, err := w.Write([]byte(body))

	if err != nil {
		fmt.Printf("Error: %s\n", err)
	}

}

func (cfg *apiConfig) DeleteChirp(w http.ResponseWriter, r *http.Request) {

	// First, Parse the chirpID
	chirpID, err := uuid.Parse(r.PathValue("chirpID"))

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Then validate the bearer token

	jwt, err := auth.GetBearerToken(r.Header)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	userID, err := auth.ValidateJWT(jwt, cfg.jwtSecret)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	//Then fetch the chirp first and if it doesn't exist, return a 404'

	chirp, err := cfg.db.GetChirpsById(r.Context(), chirpID)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(404)
		return
	}

	if chirp.UserID != userID {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// Now we can delete the chirp

	err = cfg.db.DeleteChirp(r.Context(), chirpID)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return

}

func (cfg *apiConfig) CreateNewTokenFromRefreshToken(w http.ResponseWriter, r *http.Request) {

	// get the header of the request
	token, err := auth.GetBearerToken(r.Header)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	// search the token in database if it exists

	userToken, err := cfg.db.GetUserAndRefreshToken(r.Context(), token)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	} else if userToken.ExpiresAt.Before(time.Now()) {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	} else if userToken.RevokedAt.Valid {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	// now we create a new jwt

	jwt, err := auth.MakeJWT(userToken.UserID, cfg.jwtSecret, time.Hour)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	type NewToken struct {
		Token string `json:"token"`
	}

	jwtStruct := NewToken{
		Token: jwt,
	}

	val, err := json.Marshal(&jwtStruct)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(val)

}

func (cfg *apiConfig) RevokeToken(w http.ResponseWriter, r *http.Request) {

	token, err := auth.GetBearerToken(r.Header)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(401)
		return
	}

	// now we revoke the token, but for that I first need to create a sql query

	err = cfg.db.RevokeRefreshToken(r.Context(), token)

	if err != nil {
		fmt.Printf("Error: %s\n", err)
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	return

}

func main() {

	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	JwtSECRET := os.Getenv("JWT_SECRET")
	polkaKey := os.Getenv("POLKA_KEY")
	db, err := sql.Open("postgres", dbURL)

	if err != nil {
		log.Fatal(err)
	}

	dbQueries := database.New(db)

	// NewServeMux defines routing
	mux := http.NewServeMux()
	apiConfig := &apiConfig{
		fileserverHits: atomic.Int32{},
		db:             dbQueries,
		platform:       platform,
		jwtSecret:      JwtSECRET,
		polkaKey:       polkaKey,
	}

	//Routes
	//mux.Handle("/", http.FileServer(http.Dir(".")))
	mux.Handle("/app/", apiConfig.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
	//mux.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./assets"))))
	mux.HandleFunc("GET /api/healthz", healthHandler)

	mux.HandleFunc("GET /admin/metrics", apiConfig.hitsHandler)
	mux.HandleFunc("POST /admin/reset", apiConfig.resetHits)

	// for creating user
	mux.HandleFunc("POST /api/users", apiConfig.createUser)

	// for updating a user (their own email & password)

	mux.HandleFunc("PUT /api/users", apiConfig.updateUser)

	// for creating chirps
	mux.HandleFunc("POST /api/chirps", apiConfig.createChirps)

	// for getting all chirps
	mux.HandleFunc("GET /api/chirps", apiConfig.getChirps)

	//for getting chirp by its ID
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiConfig.getChirpsById)

	mux.HandleFunc("DELETE /api/chirps/{chirpID}", apiConfig.DeleteChirp)

	// for getting user by email
	mux.HandleFunc("POST /api/login", apiConfig.getUser)

	// for getting a new token
	mux.HandleFunc("POST /api/refresh", apiConfig.CreateNewTokenFromRefreshToken)

	//for revoking the token

	mux.HandleFunc("POST /api/revoke", apiConfig.RevokeToken)

	mux.HandleFunc("POST /api/polka/webhooks", apiConfig.UpgradeUser)

	// http.Server allows configuring the server
	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	log.Fatal(server.ListenAndServe())

}
