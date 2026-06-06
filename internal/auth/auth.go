package auth

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"crypto/rand"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {

	hashedPassword, err := argon2id.CreateHash(password, argon2id.DefaultParams)

	if err != nil {
		fmt.Printf("Unable to hash password: %v", err)
		return "", err
	}

	return hashedPassword, nil

}

func CheckPasswordHash(password, hash string) (bool, error) {

	match, err := argon2id.ComparePasswordAndHash(password, hash)

	if err != nil {
		fmt.Printf("Invalid Password: %v\n", err)
		return false, err
	}

	return match, nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {

	mySigningKey := []byte(tokenSecret)

	Claims := jwt.RegisteredClaims{
		Issuer:    "chirpy-access",
		IssuedAt:  jwt.NewNumericDate(time.Now().UTC()),
		ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiresIn)),
		Subject:   userID.String(),
	}

	newJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims)

	ss, err := newJWT.SignedString(mySigningKey)

	if err != nil {
		fmt.Printf("Error: %v", err)
		return "", err
	}

	return ss, nil

}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {

	claims := jwt.RegisteredClaims{}

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(tokenSecret), nil
	})

	if err != nil {
		fmt.Printf("Error %v \n", err)
		return uuid.Nil, err
	}

	UserUUID, err := token.Claims.GetSubject()

	if err != nil {
		fmt.Printf("Error %v \n", err)
		return uuid.Nil, err
	}

	parsedUUID, err := uuid.Parse(UserUUID)

	if err != nil {
		fmt.Printf("Error %v \n", err)
		return uuid.Nil, err
	}

	return parsedUUID, nil

}

func GetBearerToken(headers http.Header) (string, error) {

	bearerToken := headers.Get("Authorization")

	if bearerToken == "" {
		return "", fmt.Errorf("Error: Unable to get Bearer Token")
	}
	if strings.HasPrefix(bearerToken, "Bearer ") {
		bearerToken = strings.TrimPrefix(bearerToken, "Bearer ")
	} else {
		fmt.Printf("Error: Invalid Bearer Token")
		return "", fmt.Errorf("Error: Invalid Bearer Token")
	}

	return bearerToken, nil

}

func MakeRefreshToken() string {

	data := make([]byte, 32)

	_, err := rand.Read(data)

	if err != nil {
		fmt.Printf("Error: %v", err)
		return ""
	}

	hexString := hex.EncodeToString(data)
	return hexString

}

func GetAPIKey(headers http.Header) (string, error) {
	ApiKey := headers.Get("Authorization")

	if ApiKey == "" {
		ApiError := fmt.Errorf("Error: Unable to get API Key")
		return "", ApiError
	}
	if strings.HasPrefix(ApiKey, "ApiKey ") {
		ApiKey = strings.TrimPrefix(ApiKey, "ApiKey ")
	} else {
		ApiError := fmt.Errorf("Error: Invalid API Key")
		return "", ApiError
	}

	return ApiKey, nil

}
