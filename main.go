package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	// llave privada
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("error generando llave privada [%v]", err.Error())
	}

	// template de certificado
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("error generando limite de llaves [%v]", err.Error())
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{"sv"},
			Organization:       []string{"haldus"},
			OrganizationalUnit: []string{"it"},
			CommonName:         "idear",
		},
		DNSNames:              []string{"haldus.test", "localhost", "127.0.0.1"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(144000 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// creación de certificado
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("error generando certificado [%v]", err.Error())
	}

	// almacenando certificado
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		log.Fatalf("error codificando certificado a PEM")
	}
	if err = os.WriteFile("cert.pem", pemCert, 0644); err != nil {
		log.Fatalf("error guardando certificado en disco [%v", err.Error())
	}
	log.Println("certificate pem escrito! - cert.pem")

	// almacenando llave privada
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("error obteniendo datos binarios de llave privada [%v]", err.Error())
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		log.Fatalf("error codificando llave privada a PEM")
	}
	if err = os.WriteFile("key.pem", pemKey, 0600); err != nil {
		log.Fatalf("error guardando llave privada en disco [%v", err.Error())
	}
	log.Println("llave privada pem escrita! - key.pem")
}
