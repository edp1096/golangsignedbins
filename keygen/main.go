package main // import "keygen"

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {
	// RSA 키 생성
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return
	}

	// 개인 키를 PKCS#8 형식으로 인코딩하여 저장
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		fmt.Println("Failed to marshal private key:", err)
		return
	}
	privateKeyPEM := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privateKeyFile, err := os.Create("private_key.pem")
	if err != nil {
		fmt.Println("Failed to create private_key.pem:", err)
		return
	}
	defer privateKeyFile.Close()
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		fmt.Println("Failed to write private_key.pem:", err)
		return
	}

	// 공개 키 추출 및 PKCS#8 형식으로 인코딩하여 저장
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("Failed to marshal public key:", err)
		return
	}
	publicKeyPEM := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyFile, err := os.Create("public_key.pem")
	if err != nil {
		fmt.Println("Failed to create public_key.pem:", err)
		return
	}
	defer publicKeyFile.Close()
	if err := pem.Encode(publicKeyFile, publicKeyPEM); err != nil {
		fmt.Println("Failed to write public_key.pem:", err)
		return
	}

	fmt.Println("Keys generated and saved successfully.")
}
