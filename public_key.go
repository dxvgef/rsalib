package rsalib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io/fs"
	"io/ioutil"
	"path/filepath"
)

type PublicKey struct {
	key *rsa.PublicKey
}

// 从原生类型中获得公钥
func (publicKey *PublicKey) FromRaw(src *rsa.PublicKey) {
	publicKey.key = src
}

// 从[]byte中获得公钥
func (publicKey *PublicKey) FromRawBytes(src []byte) (err error) {
	publicKey.key, err = x509.ParsePKCS1PublicKey(src)
	return
}

// 从Base64编码中获得公钥
func (publicKey *PublicKey) FromBase64(encoding *base64.Encoding, src []byte) error {
	buff, err := Base64Decode(encoding, src)
	if err != nil {
		return err
	}
	publicKey.key, err = x509.ParsePKCS1PublicKey(buff)
	if err != nil {
		return err
	}
	return nil
}

// 从Base64编码的文件中获得公钥
func (publicKey *PublicKey) FromBase64File(encoding *base64.Encoding, filePath string) (err error) {
	var fileData []byte
	fileData, err = ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return
	}
	return publicKey.FromBase64(encoding, fileData)
}

// 从Hex编码中获得公钥
func (publicKey *PublicKey) FromHex(src []byte) error {
	buff, err := HexDecode(src)
	if err != nil {
		return err
	}
	publicKey.key, err = x509.ParsePKCS1PublicKey(buff)
	if err != nil {
		return err
	}
	return nil
}

// 从Hex编码的文件中获得公钥
func (publicKey *PublicKey) FromHexFile(filePath string) (err error) {
	var fileData []byte
	fileData, err = ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return
	}
	return publicKey.FromHex(fileData)
}

// 公钥转为原生类型
func (publicKey *PublicKey) ToRaw() *rsa.PublicKey {
	return publicKey.key
}

// 公钥转为原生[]byte
func (publicKey *PublicKey) ToRawBytes() []byte {
	return x509.MarshalPKCS1PublicKey(publicKey.key)
}

// 公钥转为Base64编码
func (publicKey *PublicKey) ToBase64(encoding *base64.Encoding) (data []byte, err error) {
	buff := x509.MarshalPKCS1PublicKey(publicKey.key)
	data = Base64Encode(encoding, buff)
	return
}

// 公钥保存为Base64编码的文件
func (publicKey *PublicKey) ToBase64File(encoding *base64.Encoding, filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = publicKey.ToBase64(encoding)
	if err != nil {
		return
	}
	return ioutil.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 公钥转为Hex编码
func (publicKey *PublicKey) ToHex() (data []byte, err error) {
	buff := x509.MarshalPKCS1PublicKey(publicKey.key)
	data = HexEncode(buff)
	return
}

// 公钥保存为Hex编码的文件
func (publicKey *PublicKey) ToHexFile(filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = publicKey.ToHex()
	if err != nil {
		return
	}
	return ioutil.WriteFile(filepath.Clean(filePath), buff, perm)
}
