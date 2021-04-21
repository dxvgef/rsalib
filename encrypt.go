package rsalib

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
)

// 公钥加密
func (publicKey *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey.key, data)
}

// 公钥加密并转成Base64编码
func (publicKey *PublicKey) EncryptToBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	buff, err := publicKey.Encrypt(data)
	if err != nil {
		return nil, err
	}
	result := Base64Encode(encoding, buff)
	return result, nil
}

// 公钥加密并转成Hex编码
func (publicKey *PublicKey) EncryptToHex(data []byte) ([]byte, error) {
	buff, err := publicKey.Encrypt(data)
	if err != nil {
		return nil, err
	}
	result := HexEncode(buff)
	return result, nil
}

// 私钥解密
func (privateKey *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey.key, data)
}

// 私钥解密Base64编码的密文
func (privateKey *PrivateKey) DecryptFromBase64(encoding *base64.Encoding, data []byte) ([]byte, error) {
	buff := make([]byte, encoding.DecodedLen(len(data)))
	_, err := encoding.Decode(buff, data)
	if err != nil {
		return nil, err
	}
	return privateKey.Decrypt(buff)
}

// 私钥解密Hex编码的密文
func (privateKey *PrivateKey) DecryptFromHex(data []byte) ([]byte, error) {
	buff := make([]byte, hex.DecodedLen(len(data)))
	_, err := hex.Decode(buff, data)
	if err != nil {
		return nil, err
	}
	return privateKey.Decrypt(buff)
}
