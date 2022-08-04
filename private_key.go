package rsalib

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// 私钥
type PrivateKey struct {
	key         *rsa.PrivateKey
	pkcsVersion uint8
}

// 创建新私钥
func (privateKey *PrivateKey) New(bits int) (err error) {
	privateKey.key, err = rsa.GenerateKey(rand.Reader, bits)
	return
}

// 从PEM文件中获得私钥
func (privateKey *PrivateKey) FromPEMFile(filePath string) error {
	var (
		privateKeyRaw *rsa.PrivateKey
		version       uint8
	)

	// 读取PEM文件
	fileData, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return err
	}

	// 解析PEM区块（可能会有多个）
	blocks := ParsePEMBlocks(fileData)

	if len(blocks) == 0 {
		log.Println("等于0")
		log.Println(blocks)
	}

	// 解析私钥（仅解析一个，如有需要解析多个，可自行循环调用解析函数）
	if privateKeyRaw, version, err = ParseRSAPrivateKey(blocks[0].Bytes); err != nil {
		return err
	}

	privateKey.pkcsVersion = version
	return privateKey.FromRaw(privateKeyRaw)
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
	fileData, err := os.ReadFile(filepath.Clean(filePath))
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

// 获得私钥原生类型
func (privateKey PrivateKey) ToRaw() *rsa.PrivateKey {
	return privateKey.key
}

// 获得私钥的[]byte类型
func (privateKey *PrivateKey) ToRawBytes(version uint8) ([]byte, error) {
	var (
		err      error
		keyBytes []byte
	)
	switch version {
	case 1:
		keyBytes = x509.MarshalPKCS1PrivateKey(privateKey.key)
	case 8:
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privateKey.key)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("不支持指定的PKCS版本")
	}
	return keyBytes, nil
}

// 私钥保存为PEM编码的文件
func (privateKey *PrivateKey) ToPEMFile(version uint8, filePath string) error {
	buff := x509.MarshalPKCS1PrivateKey(privateKey.key)
	typeStr := "RSA PRIVATE KEY"
	if version == 8 {
		typeStr = "PRIVATE KEY"
	}
	block := &pem.Block{
		Type:  typeStr,
		Bytes: buff,
	}
	file, err := os.Create(filepath.Clean(filePath))
	if err != nil {
		return err
	}
	return pem.Encode(file, block)
}

// 私钥转为Base64数据
func (privateKey *PrivateKey) ToBase64(encoding *base64.Encoding, version uint8) (data []byte, err error) {
	var buff []byte
	buff, err = privateKey.ToRawBytes(version)
	if err != nil {
		return
	}
	data = Base64Encode(encoding, buff)
	return
}

// 私钥转为Hex编码
func (privateKey *PrivateKey) ToHex(version uint8) (data []byte, err error) {
	var buff []byte
	buff, err = privateKey.ToRawBytes(version)
	if err != nil {
		return
	}
	data = HexEncode(buff)
	return
}

// 获得PKCS版本
func (privateKey *PrivateKey) GetPKCSVersion() uint8 {
	return privateKey.pkcsVersion
}

// 获得公钥
func (privateKey *PrivateKey) GetPublicKey() PublicKey {
	return PublicKey{
		key: &privateKey.key.PublicKey,
	}
}
