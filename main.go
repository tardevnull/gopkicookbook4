package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

// RFC5280, 5.2.5
type issuingDistributionPoint struct {
	DistributionPoint          distributionPointName `asn1:"optional,tag:0"`
	OnlyContainsUserCerts      bool                  `asn1:"optional,tag:1"`
	OnlyContainsCACerts        bool                  `asn1:"optional,tag:2"`
	OnlySomeReasons            asn1.BitString        `asn1:"optional,tag:3"`
	IndirectCRL                bool                  `asn1:"optional,tag:4"`
	OnlyContainsAttributeCerts bool                  `asn1:"optional,tag:5"`
}

type distributionPointName struct {
	FullName     []asn1.RawValue  `asn1:"optional,tag:0"`
	RelativeName pkix.RDNSequence `asn1:"optional,tag:1"`
}

var oidExtensionIssuingDistributionPoint = []int{2, 5, 29, 28}

func main() {
	//PrivateKey of Self Sign CA Certificate
	privateCaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	publicCaKey := privateCaKey.Public()

	//[RFC5280]
	subjectCa := pkix.Name{
		CommonName:         "ca01",
		OrganizationalUnit: []string{"Example Org Unit"},
		Organization:       []string{"Example Org"},
		Country:            []string{"JP"},
	}

	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               subjectCa,
		NotAfter:              time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
		NotBefore:             time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	//Self Sign CA Certificate
	caCertificate, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, publicCaKey, privateCaKey)

	//Convert to ASN.1 PEM encoded form
	var f *os.File
	f, err = os.Create("ca01.crt")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caCertificate})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	f, err = os.Create("ca01.key")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	var derCaCert *x509.Certificate

	//Convert to ASN.1 DER encoded form
	derCaCert, err = x509.ParseCertificate(caCertificate)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	//Convert to ASN.1 DER encoded form
	derCaPrivateKey := x509.MarshalPKCS1PrivateKey(privateCaKey)

	err = pem.Encode(f, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: derCaPrivateKey})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	var rcs []pkix.RevokedCertificate
	rc := pkix.RevokedCertificate{
		SerialNumber:   big.NewInt(100),
		RevocationTime: time.Now(),
	}

	rcs = append(rcs, rc)

	rc = pkix.RevokedCertificate{
		SerialNumber:   big.NewInt(108),
		RevocationTime: time.Now(),
	}

	rcs = append(rcs, rc)

	//Create issuingDistributionPoint Extension
	dp := distributionPointName{
		FullName: []asn1.RawValue{
			{Tag: 6, Class: 2, Bytes: []byte("http://www.example.com/example.crl")},
		},
	}
	idp := issuingDistributionPoint{
		DistributionPoint: dp,
	}

	v, err := asn1.Marshal(idp)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	cdpExt := pkix.Extension{
		Id:       oidExtensionIssuingDistributionPoint,
		Critical: true,
		Value:    v,
	}

	crlTpl := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: rcs,
		Number:              big.NewInt(2),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(24 * time.Hour),
		ExtraExtensions:     []pkix.Extension{cdpExt},
	}

	var derCrl []byte
	derCrl, err = x509.CreateRevocationList(rand.Reader, crlTpl, derCaCert, privateCaKey)
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	f, err = os.Create("example.crl")
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}

	err = pem.Encode(f, &pem.Block{Type: "X509 CRL", Bytes: derCrl})
	if err != nil {
		log.Fatalf("ERROR:%v\n", err)
	}
	err = f.Close()

}
