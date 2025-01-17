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
	DefaultOutputDir := "/tmp/"
	File := flag.String("f", DefaultInFile, fmt.Sprintf("Path for file, default = %s", DefaultInFile))
	OutputDir := flag.String("o", DefaultOutputDir, fmt.Sprintf("Output directory, default = %s", DefaultOutputDir))
	flag.Parse()

	// Create directory if not exist.
	if err := os.MkdirAll(*OutputDir, 0755); err != nil {
		fmt.Println("Error creating directory:", err)
		return
	}

	// Read and unmarshal YAML file
	F, err := ioutil.ReadFile(*File)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	if err = yaml.Unmarshal(F, &infile); err != nil {
		fmt.Println("YAML unmarshal error:", err)
		return
	}

	// Create private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}

	if err = writePEMFile(*OutputDir+infile.Host+".key", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(priv)); err != nil {
		fmt.Println("Error writing key file:", err)
		return
	}

	// Create CSR
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
					Bytes: []byte(infile.EMail),
				},
			},
		},
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}, priv)
	if err != nil {
		fmt.Println("Error creating CSR:", err)
		return
	}

	if err = writePEMFile(*OutputDir+infile.Host+".csr", "CERTIFICATE REQUEST", csr); err != nil {
		fmt.Println("Error writing CSR file:", err)
		return
	}
}

// writePEMFile writes a PEM encoded file with the given type and bytes.
func writePEMFile(filename, pemType string, bytes []byte) error {
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, &pem.Block{Type: pemType, Bytes: bytes})
}
