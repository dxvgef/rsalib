package rsalib

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
)

// 私钥签名
func (privateKey *PrivateKey) Sign(data []byte, ch crypto.Hash) ([]byte, error) {
	hash := ch.New()
	_, err := hash.Write(data)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, privateKey.key, ch, hash.Sum(nil))
}

// 公钥验签
func (publicKey *PublicKey) Verify(data, sign []byte, ch crypto.Hash) bool {
	hash := ch.New()
	_, err := hash.Write(data)
	if err != nil {
		return false
	}
	return rsa.VerifyPKCS1v15(publicKey.key, ch, hash.Sum(nil), sign) == nil
}

// 私钥签名并转成Base64编码
func (privateKey *PrivateKey) SignToBase64(encoding *base64.Encoding, data []byte, ch crypto.Hash) ([]byte, error) {
	sign, err := privateKey.Sign(data, ch)
	if err != nil {
		return nil, err
	}
	dst := Base64Encode(encoding, sign)
	return dst, nil
}

// 私钥签名并转成Hex编码
func (privateKey *PrivateKey) SignToHex(data []byte, ch crypto.Hash) ([]byte, error) {
	cipher, err := privateKey.Sign(data, ch)
	if err != nil {
		return nil, err
	}
	dst := HexEncode(cipher)
	return dst, nil
}
