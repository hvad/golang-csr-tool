package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/yaml.v2"
)

var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

type Infile struct {
	Host    string `yaml:"Host"`
	EMail   string `yaml:"EMail"`
	CName   string `yaml:"CName"`
	COuntry string `yaml:"COuntry"`
	STate   string `yaml:"STate"`
	CIty    string `yaml:"CIty"`
	O       string `yaml:"O"`
	OU      string `yaml:"OU"`
}

func main() {

	var infile Infile

	DefaultInFile := "~/file.yml"
	DefaultOutputDir := "/tmp/pki"
	File := flag.String("f", DefaultInFile, fmt.Sprintf("Path for file, default = %s", DefaultInFile))
	OutputDir := flag.String("o", DefaultOutputDir, fmt.Sprintf("Output directory, default = %s", DefaultOutputDir))
	flag.Parse()

	if err := os.Mkdir(*OutputDir, 0755); err != nil && !os.IsExist(err) {
		fmt.Println("Error to create directory.")

	}

	F, err := ioutil.ReadFile(*File)
	if err != nil {
		fmt.Println("Error to get file.")
	}

	err = yaml.Unmarshal(F, &infile)
	if err != nil {
		fmt.Println("YAML error.")
	}

	// Create private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Can't generate Key.")
	}

	keyOut, err := os.OpenFile("out.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Can't write Key file.")
	}
	defer keyOut.Close()

	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}); err != nil {
		fmt.Println("PEM error for Key.")
	}

	// Create template for CSR
	emailAddress := infile.EMail

	subj := pkix.Name{
		CommonName:         infile.CName,
		Country:            []string{infile.COuntry},
		Province:           []string{infile.STate},
		Locality:           []string{infile.CIty},
		Organization:       []string{infile.O},
		OrganizationalUnit: []string{infile.OU},
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

	// Create CSR
	csrOut, err := os.OpenFile("out.csr", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		fmt.Println("Can't write CSR file.")
	}
	defer csrOut.Close()

	csr, err := x509.CreateCertificateRequest(rand.Reader, &template, priv)
	if err != nil {
		fmt.Println("Can't create CSR.")
	}

	if err := pem.Encode(csrOut, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}); err != nil {
		fmt.Println("PEM error for CSR.")
	}

}
