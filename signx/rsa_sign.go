package signx

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
)

const (
	RSA  string = "RSA"
	RSA2 string = "RSA2"
)

// RsaSign RSA签名
// signParams：签名参数
// signType：签名类型，RSA 或 RSA2
// privateKey：应用私钥，支持PKCS1和PKCS8
func RsaSign(signParams []byte, signType string, privateKey *rsa.PrivateKey) (sign string, err error) {
	var (
		h              hash.Hash
		hashType       crypto.Hash
		encryptedBytes []byte
	)

	switch signType {
	case RSA:
		h = sha1.New()
		hashType = crypto.SHA1
	case RSA2:
		h = sha256.New()
		hashType = crypto.SHA256
	default:
		h = sha256.New()
		hashType = crypto.SHA256
	}

	if _, err = h.Write(signParams); err != nil {
		return
	}
	if encryptedBytes, err = rsa.SignPKCS1v15(rand.Reader, privateKey, hashType, h.Sum(nil)); err != nil {
		return
	}
	sign = base64.StdEncoding.EncodeToString(encryptedBytes)
	return
}
