package cryptoutils

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/renyangang/gotools/logger"
)

func Base64Decode(src string) []byte {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	n, err := base64.StdEncoding.Decode(dst, []byte(src))
	if err != nil {
		fmt.Println("decode error:", err)
		return nil
	}
	return dst[:n]
}

func Base64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func SHA256SumInfo(info string) string {
	h := sha256.New()
	return base64.StdEncoding.EncodeToString(h.Sum([]byte(info)))
}

func NormalJsonStr(src string) string {
	begin := strings.Index(src, "{")
	end := strings.LastIndex(src, "}")
	return src[begin : end+1]
}

// PKCS7Padding 对明文进行填充
func PKCS7Padding(plainText []byte, blockSize int) []byte {
	padding := blockSize - len(plainText)%blockSize
	if padding == 0 {
		return plainText
	}
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plainText, padText...)
}

func EncodeAES(src, keyStr, ivStr string) (string, error) {
	key := []byte(keyStr)
	iv := []byte(ivStr)
	ciphertext, err := BSEncodeAES([]byte(src), key, iv)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func BSEncodeAES(src, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("EncodeAES NewCipher error:", err)
		return nil, err
	}
	plainbuf := PKCS7Padding(src, block.BlockSize())
	ciphertext := make([]byte, len(plainbuf))
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(ciphertext, plainbuf)
	return ciphertext, nil
}
func DecodeAES(src, keyStr, ivStr string) ([]byte, error) {
	key := []byte(keyStr)
	iv := []byte(ivStr)
	srcBytes, err := base64.StdEncoding.DecodeString(src)
	if err != nil {
		logger.Error("DecodeAES DecodeString error:", err)
		return nil, err
	}
	return BSDecodeAES(srcBytes, key, iv)
}
func BSDecodeAES(src, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		logger.Error("DecodeAES NewCipher error:", err)
		return nil, err
	}
	if len(src) < aes.BlockSize {
		logger.Error("ciphertext too short")
		return nil, errors.New("ciphertext too short")
	}
	// CBC mode always works in whole blocks.
	if len(src)%aes.BlockSize != 0 {
		logger.Error("ciphertext is not a multiple of the block size")
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(src))
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(plainText, src)
	return plainText, nil
}

func VerifyRSA(ciphertext []byte, signStr, publicKey string) (bool, error) {
	x509EncodedKey := Base64Decode(publicKey)
	pubKey, err := x509.ParsePKIXPublicKey(x509EncodedKey)
	if err != nil {
		logger.Error("failed to parse public key:", err)
		return false, err
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		logger.Error("public key is not an RSA key")
		return false, errors.New("public key is not an RSA key")
	}
	signature := Base64Decode(signStr)

	hashed := sha256.Sum256(ciphertext)

	err = rsa.VerifyPKCS1v15(rsaPubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		logger.Error("Error from verification: ", err)
		return false, err
	}
	return true, nil
}

func SignRSA(data []byte, priKeyStr string) (string, error) {
	x509EncodedKey := Base64Decode(priKeyStr)
	privateKey, err := x509.ParsePKCS1PrivateKey(x509EncodedKey)
	if err != nil {
		logger.Error("failed to parse private key:", err)
		return "", err
	}
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		logger.Error("Error from signing: ", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func GenRSAKeys() (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logger.Error("failed to generate private key:", err)
		return "", "", err
	}
	x509EncodedPrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	priKeyStr := base64.StdEncoding.EncodeToString(x509EncodedPrivateKey)
	publicKey := &privateKey.PublicKey
	x509EncodedPublicKey, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		logger.Error("failed to marshal public key:", err)
		return "", "", err
	}
	pubKeyStr := base64.StdEncoding.EncodeToString(x509EncodedPublicKey)
	return priKeyStr, pubKeyStr, nil
}
