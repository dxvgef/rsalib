package rsalib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io/fs"
	"io/ioutil"
	"path/filepath"
	"strings"
)

// 私钥
type PrivateKey struct {
	key *rsa.PrivateKey
	// pkcsVersion PKCSVersion
}

// 创建新私钥
func (privateKey *PrivateKey) New(bits int) (err error) {
	privateKey.key, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	return nil
}

// 从原生类型中获得私钥
func (privateKey *PrivateKey) FromRaw(src *rsa.PrivateKey) (err error) {
	if src == nil {
		err = errors.New("不是有效的RSA密钥")
		return
	}
	err = src.Validate()
	if err != nil {
		return
	}
	privateKey.key = src
	return
}

// 从[]byte中获得私钥
func (privateKey *PrivateKey) FromRawBytes(src []byte) (err error) {
	var (
		key      *rsa.PrivateKey
		pkcs8Key interface{}
		ok       bool
	)
	key, err = x509.ParsePKCS1PrivateKey(src)
	if err != nil {
		if !strings.Contains(err.Error(), "PKCS8") {
			return
		}
		// 尝试PKCS8
		pkcs8Key, err = x509.ParsePKCS8PrivateKey(src)
		if err != nil {
			return
		}
		key, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			err = errors.New("不是有效的RSA私钥")
			return
		}
	}
	privateKey.key = key
	return
}

// 从Base64数据中获得私钥
func (privateKey *PrivateKey) FromBase64(encoding *base64.Encoding, src []byte) error {
	buff, err := Base64Decode(encoding, src)
	if err != nil {
		return err
	}
	return privateKey.FromRawBytes(buff)
}

// 从Base64文件中获得私钥
func (privateKey *PrivateKey) FromBase64File(encoding *base64.Encoding, filePath string) error {
	fileData, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return err
	}
	return privateKey.FromBase64(encoding, fileData)
}

// 从Hex数据中获得私钥
func (privateKey *PrivateKey) FromHex(src []byte) error {
	buff, err := HexDecode(src)
	if err != nil {
		return err
	}
	return privateKey.FromRawBytes(buff)
}

// 从Hex文件中获得私钥
func (privateKey *PrivateKey) FromHexFile(filePath string) error {
	fileData, err := ioutil.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return err
	}
	return privateKey.FromHex(fileData)
}

// 获得私钥原生类型
func (privateKey PrivateKey) ToRaw() *rsa.PrivateKey {
	return privateKey.key
}

// 获得私钥的[]byte类型
func (privateKey *PrivateKey) ToRawBytes(version PKCSVersion) ([]byte, error) {
	var (
		err      error
		keyBytes []byte
	)
	switch version {
	case PKCS1:
		keyBytes = x509.MarshalPKCS1PrivateKey(privateKey.key)
	case PKCS8:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey.key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("不支持指定的PKCS版本")
	}
	return keyBytes, nil
}

// 私钥转为Base64数据
func (privateKey *PrivateKey) ToBase64(encoding *base64.Encoding, version PKCSVersion) (data []byte, err error) {
	var buff []byte
	buff, err = privateKey.ToRawBytes(version)
	if err != nil {
		return
	}
	data = Base64Encode(encoding, buff)
	return
}

// 私钥保存为Base64编码的文件
func (privateKey *PrivateKey) ToBase64File(encoding *base64.Encoding, version PKCSVersion, filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = privateKey.ToBase64(encoding, version)
	if err != nil {
		return
	}
	return ioutil.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 私钥转为Hex编码
func (privateKey *PrivateKey) ToHex(version PKCSVersion) (data []byte, err error) {
	var buff []byte
	buff, err = privateKey.ToRawBytes(version)
	if err != nil {
		return
	}
	data = HexEncode(buff)
	return
}

// 私钥保存为Hex编码的文件
func (privateKey *PrivateKey) ToHexFile(version PKCSVersion, filePath string, perm fs.FileMode) (err error) {
	var buff []byte
	buff, err = privateKey.ToHex(version)
	if err != nil {
		return
	}
	return ioutil.WriteFile(filepath.Clean(filePath), buff, perm)
}

// 获得公钥
func (privateKey *PrivateKey) GetPublicKey() PublicKey {
	return PublicKey{
		key: &privateKey.key.PublicKey,
	}
}
