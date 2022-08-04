package rsalib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
	"unsafe"
)

// []byte转string
func BytesToString(value []byte) string {
	return *(*string)(unsafe.Pointer(&value)) // nolint
}

// 字符串转[]byte
func StringToBytes(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s)) // nolint
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h)) // nolint
}

// Base64编码
func Base64Encode(encoding *base64.Encoding, src []byte) []byte {
	dst := make([]byte, encoding.EncodedLen(len(src)))
	encoding.Encode(dst, src)
	return dst
}

// Base64解码
func Base64Decode(encoding *base64.Encoding, src []byte) ([]byte, error) {
	dst := make([]byte, encoding.DecodedLen(len(src)))
	_, err := encoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

// Hex编码
func HexEncode(src []byte) []byte {
	dst := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(dst, src)
	return dst
}

// Hex解码
func HexDecode(src []byte) ([]byte, error) {
	dst := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

// ParsePEMBlocks 解析PEM区块
func ParsePEMBlocks(data []byte) []*pem.Block {
	var (
		blocks []*pem.Block
		block  *pem.Block
		rest   []byte
	)
	block, rest = pem.Decode(data)
	if block != nil {
		blocks = append(blocks, block)
		for len(rest) > 0 {
			block, rest = pem.Decode(rest)
			if block != nil {
				blocks = append(blocks, block)
			}
		}
	}
	return blocks
}

// 解析RSA私钥，自动识别PKCS1和PKCS8
func ParseRSAPrivateKey(data []byte) (privateKey *rsa.PrivateKey, version uint8, err error) {
	version = 1
	// 尝试PKCS1
	privateKey, err = ParsePKCS1PrivateKey(data)
	if err != nil {
		// 如果PKCS1和PKCS8，直认为无效
		if !strings.Contains(err.Error(), "PKCS8") {
			return
		}
		// 尝试PKCS8
		privateKey, err = ParsePKCS8PrivateKey(data)
		if err != nil {
			return
		}
		version = 8
	}
	return
}

// 解析PKCS1私钥
func ParsePKCS1PrivateKey(data []byte) (*rsa.PrivateKey, error) {
	return x509.ParsePKCS1PrivateKey(data)
}

// 解析PKCS8私钥
func ParsePKCS8PrivateKey(data []byte) (privateKey *rsa.PrivateKey, err error) {
	var (
		parsedKey interface{}
		ok        bool
	)
	parsedKey, err = x509.ParsePKCS8PrivateKey(data)
	if err != nil {
		return
	}
	privateKey, ok = parsedKey.(*rsa.PrivateKey)
	if !ok {
		err = errors.New("不是有效的RSA私钥")
		return
	}
	return
}

// ParseRSAPublicKey 解析RSA公钥
func ParseRSAPublicKey(data []byte) (publicKey *rsa.PublicKey, err error) {
	var (
		parsedKey interface{}
		ok        bool
		cert      *x509.Certificate
	)

	parsedKey, err = x509.ParsePKIXPublicKey(data)
	if err != nil {
		cert, err = x509.ParseCertificate(data)
		if err == nil {
			parsedKey = cert.PublicKey
		} else {
			return
		}
	}

	publicKey, ok = parsedKey.(*rsa.PublicKey)
	if !ok {
		err = errors.New("不是有效的RSA公钥")
		return
	}

	return
}
