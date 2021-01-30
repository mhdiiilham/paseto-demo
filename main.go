package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"time"

	_ "github.com/joho/godotenv/autoload"
	"github.com/o1egl/paseto"
)

func main() {
	fmt.Println("Hello, PASETO")

	symmetricKey := []byte(os.Getenv("SYMMETRICT_KEY"))
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)

	payload := &PasetoCustomClaim{
		Username: "w8rloO",
		Fullname: "Muhammad Ilham",
		Email:    "muhd.iiilham@gmail.com",
	}

	symmetricToken := GenerateSymmetricToken(payload, symmetricKey)
	symmetricTokenDecrypted, symmetricTokenFooter, _ := SymmetricTokenDecrypter(symmetricToken, symmetricKey)
	fmt.Println("Symmetric Token: \n", symmetricToken)
	fmt.Println("Symmetric Token Payload: \n", symmetricTokenDecrypted)
	fmt.Println("Symmetric Token Footer: \n", symmetricTokenFooter)

	asymmetricToken := AsymmetricTokenSigner(payload, privateKey)
	asymmetricTokenVerified, aysmasymmetricTokenFooter, _ := AsymmetricTokenVerifier(asymmetricToken, publicKey)
	fmt.Println("Asymmetric Key:", asymmetricToken)
	fmt.Println("Asymmetric Token Payload: \n", asymmetricTokenVerified)
	fmt.Println("Asymmetric Token Footer: \n", aysmasymmetricTokenFooter)
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

// AsymmetricTokenSigner function
// is to generate PASETO token private mode
func AsymmetricTokenSigner(payload *PasetoCustomClaim, privateKey ed25519.PrivateKey) string {
	var err error
	var token string
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

	token, err = paseto.NewV2().Sign(privateKey, jsonToken, "This is my ugly foot")
	if err != nil {
		fmt.Println("Error:", err.Error())
		return ""
	}

	return token
}

// SymmetricTokenDecrypter function
// is user to decrypt
func SymmetricTokenDecrypter(symmetricToken string, symmetricKey []byte) (*paseto.JSONToken, string, error) {
	var newJSONToken paseto.JSONToken
	var newFooter string

	if err := paseto.NewV2().Decrypt(symmetricToken, symmetricKey, &newJSONToken, &newFooter); err != nil {
		return nil, "", err
	}

	return &newJSONToken, newFooter, nil
}

// AsymmetricTokenVerifier function
// use to verify Private Token
func AsymmetricTokenVerifier(asymmetricToken string, publicKey ed25519.PublicKey) (*paseto.JSONToken, string, error) {
	var newJSONToken paseto.JSONToken
	var newFooter string

	if err := paseto.NewV2().Verify(asymmetricToken, publicKey, &newJSONToken, &newFooter); err != nil {
		return nil, "", err
	}

	return &newJSONToken, newFooter, nil
}
