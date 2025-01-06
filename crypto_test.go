package main

import (
	"fmt"
	"testing"

	"github.com/renyangang/gotools/cryptoutils"
)

func TestRSAEncrypt(t *testing.T) {
	priKeyStr, pubKeyStr, err := cryptoutils.GenRSAKeys()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := cryptoutils.EncodeRSA([]byte("Hello World"), pubKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := cryptoutils.DecodeRSA(enc, priKeyStr)
	if err != nil {
		t.Fatal(err)
	}
	if string(dec) != "Hello World" {
		t.Fatal("dec != Hello World")
	}
	fmt.Println(string(dec))
}
