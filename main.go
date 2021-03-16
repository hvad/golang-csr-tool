package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

func main() {

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	emailAddress := "email@example.com"

	subj := pkix.Name{
		CommonName:         "example.com",
		Country:            []string{"FR"},
		Province:           []string{"Some-State"},
		Locality:           []string{"City"},
		Organization:       []string{"Company LTD"},
		OrganizationalUnit: []string{"IT"},
		ExtraNames: []pkix.AttributeTypeAndValue{
			{
				Type: oidEmailAddress,
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		},
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	csrOut, _ := os.OpenFile("out.csr", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})
	defer csrOut.Close()

	keyOut, _ := os.OpenFile("out.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	defer keyOut.Close()

}
