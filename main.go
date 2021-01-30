package main

import (
	"fmt"
	"os"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/o1egl/paseto"
)

func main() {
	fmt.Println("Hello, PASETO")

	symmetricKey := []byte(os.Getenv("SYMMETRICT_KEY"))

	payload := &PasetoCustomClaim{
		Username: "w8rloO",
		Fullname: "Muhammad Ilham",
		Email:    "muhd.iiilham@gmail.com",
	}

	symmetricToken := GenerateSymmetricToken(payload, symmetricKey)
	symmetricTokenDecrypted, symmetricTokenFooter, _ := SymmetricTokenDecrypter(symmetricToken, symmetricKey)
	fmt.Print("Symmetric Token: \n", symmetricToken)
	fmt.Println("Symmetric Token Payload: \n", symmetricTokenDecrypted)
	fmt.Println("Symmetric Token Footer: \n", symmetricTokenFooter)
}

// PasetoCustomClaim struct
// is type that passed to GenerateToken function
type PasetoCustomClaim struct {
	Fullname string
	Username string
	Email    string
}

// GenerateSymmetricToken function
// use to generate PASETO token
func GenerateSymmetricToken(payload *PasetoCustomClaim, symmetricKey []byte) string {
	jti := os.Getenv("JTI")
	now := time.Now()
	exp := now.Add(168 * time.Hour)
	nbt := now

	jsonToken := paseto.JSONToken{
		Audience:   "piigy",
		Issuer:     "SlimyP1G",
		Jti:        jti,
		Subject:    "Access Token",
		IssuedAt:   now,
		Expiration: exp,
		NotBefore:  nbt,
	}

	jsonToken.Set("Fullname", payload.Fullname)
	jsonToken.Set("Username", payload.Username)
	jsonToken.Set("Email", payload.Email)

	token, err := paseto.NewV2().Encrypt(symmetricKey, jsonToken, "This is my foot tho")
	if err != nil {
		fmt.Println("Error: ", err.Error())
		return ""
	}

	return token
}

// SymmetricTokenDecrypter function
// is user to decrypt
func SymmetricTokenDecrypter(symmetricToken string, symmetricKey []byte) (*paseto.JSONToken, *string, error) {
	var newJSONToken paseto.JSONToken
	var newFooter string

	if err := paseto.NewV2().Decrypt(symmetricToken, symmetricKey, &newJSONToken, &newFooter); err != nil {
		return nil, nil, err
	}

	return &newJSONToken, &newFooter, nil
}
