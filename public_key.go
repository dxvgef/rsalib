package rsalib

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

type PublicKey struct {
	key         *rsa.PublicKey
	pkcsVersion uint8
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

// 生成PEM文件
func (publicKey *PublicKey) ToPEMFile(version uint8, filePath string) error {
	buff, err := x509.MarshalPKIXPublicKey(publicKey.ToRaw())
	if err != nil {
		return err
	}
	typeStr := "RSA PUBLIC KEY"
	if version == 8 {
		typeStr = "PUBLIC KEY"
	}
	block := &pem.Block{
		Type:  typeStr,
		Bytes: buff,
	}

	var file *os.File
	file, err = os.Create(filepath.Clean(filePath))
	if err != nil {
		return err
	}
	return pem.Encode(file, block)
}

// 从PEM文件中获得公钥
func (publicKey *PublicKey) FromPEMFile(filePath string) (err error) {
	var (
		publicKeyRaw *rsa.PublicKey
		version      uint8
	)

	// 读取PEM文件
	fileData, err := os.ReadFile(filepath.Clean(filePath))
	if err != nil {
		return err
	}

	// 解析PEM区块（可能会有多个）
	blocks := ParsePEMBlocks(fileData)

	if len(blocks) == 0 {
		err = errors.New("PEM文件无效")
		return
	}

	// 解析私钥（仅解析一个，如有需要解析多个，可自行循环调用解析函数）
	if publicKeyRaw, version, err = ParseRSAPublicKey(blocks[0].Bytes); err != nil {
		return
	}

	publicKey.pkcsVersion = version
	publicKey.FromRaw(publicKeyRaw)
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

// 公钥转为原生类型
func (publicKey PublicKey) ToRaw() *rsa.PublicKey {
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

// 公钥转为Hex编码
func (publicKey *PublicKey) ToHex() (data []byte, err error) {
	buff := x509.MarshalPKCS1PublicKey(publicKey.key)
	data = HexEncode(buff)
	return
}
