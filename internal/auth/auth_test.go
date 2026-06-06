package auth

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestValidateJWT(t *testing.T) {
	// create a new useriD with uuid.New()

	userId := uuid.New()

	//use makeJWT to create a token

	jwt, err := MakeJWT(userId, "secret", time.Minute*2)
	if err != nil {
		t.Error(err)
	}
	res, err := ValidateJWT(jwt, "secret")

	if err != nil {
		t.Error(err)
	}
	if res != userId {
		t.Error("User ID does not match")
	}
}

func TestExpiredToken(t *testing.T) {

	// create a uuid

	userID := uuid.New()

	// make JWT

	jwt, err := MakeJWT(userID, "secret", 0)

	if err != nil {
		t.Error(err)
	}

	// validate JWT which should fail as its expired

	_, err = ValidateJWT(jwt, "secret")

	if err == nil {
		t.Error("Token should have expired")
	}

}

func TestSecretMismatch(t *testing.T) {

	// creat user with uuid

	userID := uuid.New()

	// make JWT

	jwt, err := MakeJWT(userID, "secret", time.Minute*2)

	if err != nil {
		t.Error(err)
	}

	// validate JWT with wrong secret

	_, err = ValidateJWT(jwt, "wrong secret")

	if err == nil {
		t.Error("Secret mismatch should have failed")
	}
}
