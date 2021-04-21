package rsalib

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unsafe"
)

const (
	publicKeyPrefix = "-----BEGIN PUBLIC KEY-----"
	publicKeySuffix = "-----END PUBLIC KEY-----"

	PKCS1Prefix = "-----BEGIN RSA PRIVATE KEY-----"
	PKCS1Suffix = "-----END RSA PRIVATE KEY-----"

	PKCS8Prefix = "-----BEGIN PRIVATE KEY-----"
	PKCS8Suffix = "-----END PRIVATE KEY-----"
)

// 加密标准的版本
type PKCSVersion uint8

const (
	PKCS1 PKCSVersion = 1
	PKCS8 PKCSVersion = 8
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

// 格式化公钥
func FormatPublicKey(key string) []byte {
	return formatKey(key, publicKeyPrefix, publicKeySuffix, 64)
}

// 格式化私钥
func FormatPKCSPrivateKey(key string, version PKCSVersion) []byte {
	switch version {
	case PKCS1:
		return formatKey(key, PKCS1Prefix, PKCS1Suffix, 64)
	case PKCS8:
		return formatKey(key, PKCS8Prefix, PKCS8Suffix, 64)
	}
	return nil
}

func formatKey(raw, prefix, suffix string, lineCount int) []byte {
	var err error
	raw = strings.Replace(raw, PKCS8Prefix, "", 1)
	raw = strings.Replace(raw, PKCS8Suffix, "", 1)
	if raw == "" {
		return nil
	}
	raw = strings.Replace(raw, prefix, "", 1)
	raw = strings.Replace(raw, suffix, "", 1)
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "\n", "")
	raw = strings.ReplaceAll(raw, "\r", "")
	raw = strings.ReplaceAll(raw, "\t", "")

	var sl = len(raw)
	var c = sl / lineCount
	if sl%lineCount > 0 {
		c++
	}

	var buf bytes.Buffer
	if _, err = buf.WriteString(prefix + "\n"); err != nil {
		return nil
	}
	for i := 0; i < c; i++ {
		var b = i * lineCount
		var e = b + lineCount
		if e > sl {
			if _, err = buf.WriteString(raw[b:]); err != nil {
				return nil
			}
		} else {
			if _, err = buf.WriteString(raw[b:e]); err != nil {
				return nil
			}
		}
		if _, err = buf.WriteString("\n"); err != nil {
			return nil
		}
	}
	if _, err = buf.WriteString(suffix); err != nil {
		return nil
	}
	return buf.Bytes()
}
