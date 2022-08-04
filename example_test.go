package rsalib

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"os"
	"testing"
)

var (
	privateKey PrivateKey
	publicKey  PublicKey
	// privateKeyPWD     = []byte("123456")
	plaintext = "abc"
)

// 测试前准备
func TestMain(m *testing.M) {
	// 开始运行测试用例
	m.Run()
	os.Exit(0)
}

// 测试入口
func TestAll(t *testing.T) {
	// ------------------- 私钥 -----------------------------
	// 生成私钥
	t.Run("TestPrivateKeyNew", TestPrivateKey_New)
	// PEM文件
	t.Run("TestPrivateKey_PEMFile", TestPrivateKey_PEMFile)
	// *rsa.PrivateKey
	t.Run("TestPrivateKey_Raw", TestPrivateKey_Raw)
	// 原生字节码
	t.Run("TestPrivateKey_RawBytes", TestPrivateKey_RawBytes)
	// base64
	t.Run("TestPrivateKey_Base64", TestPrivateKey_Base64)
	// hex
	t.Run("TestPrivateKey_Hex", TestPrivateKey_Hex)

	// ------------------- 私钥 -----------------------------
	// 获得公钥
	t.Run("TestGetPublicKey", TestGetPublicKey)
	// PEM文件
	t.Run("TestPublicKey_PEM", TestPublicKey_PEM)
	// *rsa.PublicKey
	t.Run("TestPublicKey_ToRaw", TestPublicKey_ToRaw)
	// 原生公钥字节码
	t.Run("TestPublicKey_RawBytes", TestPublicKey_RawBytes)
	// base64
	t.Run("TestPublicKey_Base64", TestPublicKey_Base64)
	// hex
	t.Run("TestPublicKey_Hex", TestPublicKey_Hex)

	// 签名
	t.Run("TestSign", TestSign)
	// 使用base64编码签名/校验
	t.Run("TestSignByBase64", TestSignByBase64)
	// 使用hex编码签名/校验
	t.Run("TestSignByHex", TestSignByHex)

	// 加解密
	t.Run("TestEncrypt", TestEncrypt)
	// 使用base64编码加解密
	t.Run("TestEncryptByBase64", TestEncryptByBase64)
	// 使用hex编码加解密
	t.Run("TestEncryptByHex", TestEncryptByHex)
}

// 生成私钥
func TestPrivateKey_New(t *testing.T) {
	err := privateKey.New(2048)
	if err != nil {
		t.Error(err)
	}
}

// *rsa.PrivateKey
func TestPrivateKey_Raw(t *testing.T) {
	err := privateKey.FromRaw(privateKey.ToRaw())
	if err != nil {
		t.Error(err)
	}
}

// 原生字节码
func TestPrivateKey_RawBytes(t *testing.T) {
	src, err := privateKey.ToRawBytes(1)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromRawBytes(src)
	if err != nil {
		t.Error(err)
	}
}

// 测试PEM文件
func TestPrivateKey_PEMFile(t *testing.T) {
	filePath := "./private_pem.key"
	err := privateKey.ToPEMFile(1, filePath)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromPEMFile(filePath)
	if err != nil {
		t.Error(err)
	}
}

// base64
func TestPrivateKey_Base64(t *testing.T) {
	src, err := privateKey.ToBase64(base64.RawStdEncoding, 1)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromBase64(base64.RawStdEncoding, src)
	if err != nil {
		t.Error(err)
	}
}

// hex
func TestPrivateKey_Hex(t *testing.T) {
	src, err := privateKey.ToHex(1)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromHex(src)
	if err != nil {
		t.Error(err)
	}
}

// 从私钥中获得公钥
func TestGetPublicKey(t *testing.T) {
	publicKey = privateKey.GetPublicKey()
}

// PEM
func TestPublicKey_PEM(t *testing.T) {
	filePath := "./public_pem.key"
	if err := publicKey.ToPEMFile(1, filePath); err != nil {
		t.Error(err)
	}
	if err := publicKey.FromPEMFile(filePath); err != nil {
		t.Error(err)
		return
	}
}

// 获取原生类型的公钥
func TestPublicKey_ToRaw(t *testing.T) {
	publicKey.FromRaw(publicKey.ToRaw())
}

// 原生公钥字节码
func TestPublicKey_RawBytes(t *testing.T) {
	data := publicKey.ToRawBytes()
	err := publicKey.FromRawBytes(data)
	if err != nil {
		t.Error(err)
	}
}

// base64
func TestPublicKey_Base64(t *testing.T) {
	data, err := publicKey.ToBase64(base64.RawStdEncoding)
	if err != nil {
		t.Error(err)
		return
	}
	err = publicKey.FromBase64(base64.RawStdEncoding, data)
	if err != nil {
		t.Error(err)
	}
}

// hex
func TestPublicKey_Hex(t *testing.T) {
	data, err := publicKey.ToHex()
	if err != nil {
		t.Error(err)
		return
	}
	err = publicKey.FromHex(data)
	if err != nil {
		t.Error(err)
	}
}

// 加解密
func TestEncrypt(t *testing.T) {
	cipher, err := publicKey.Encrypt([]byte(plaintext))
	if err != nil {
		t.Error(err)
		return
	}
	plain, err2 := privateKey.Decrypt(cipher)
	if err2 != nil {
		t.Error(err2)
		return
	}
	if !bytes.Equal(plain, []byte(plaintext)) {
		t.Error("加解密结果不同")
	}
}

// 使用base64编码加解密
func TestEncryptByBase64(t *testing.T) {
	cipher, err := publicKey.EncryptToBase64(base64.RawURLEncoding, []byte(plaintext))
	if err != nil {
		t.Error(err)
		return
	}
	plain, err2 := privateKey.DecryptFromBase64(base64.RawURLEncoding, cipher)
	if err2 != nil {
		t.Error(err2)
		return
	}
	if !bytes.Equal(plain, []byte(plaintext)) {
		t.Error("加解密结果不同")
	}
}

// 使用hex编码加解密
func TestEncryptByHex(t *testing.T) {
	cipher, err := publicKey.EncryptToHex([]byte(plaintext))
	if err != nil {
		t.Error(err)
		return
	}
	plain, err2 := privateKey.DecryptFromHex(cipher)
	if err2 != nil {
		t.Error(err2)
		return
	}
	if !bytes.Equal(plain, []byte(plaintext)) {
		t.Error("加解密结果不同")
	}
}

// 签名/校验
func TestSign(t *testing.T) {
	sign, err := privateKey.Sign([]byte(plaintext), crypto.SHA256)
	if err != nil {
		t.Error(err)
		return
	}
	if !publicKey.Verify([]byte(plaintext), sign, crypto.SHA256) {
		t.Error("验签失败")
	}
}

// 使用base64编码签名/校验
func TestSignByBase64(t *testing.T) {
	signBase64, err := privateKey.SignToBase64(base64.RawURLEncoding, []byte(plaintext), crypto.SHA256)
	if err != nil {
		t.Error(err)
		return
	}
	sign, err2 := Base64Decode(base64.RawURLEncoding, signBase64)
	if err2 != nil {
		t.Error(err2)
		return
	}
	if !publicKey.Verify([]byte(plaintext), sign, crypto.SHA256) {
		t.Error("验签失败")
	}
}

// 使用hex编码签名/校验
func TestSignByHex(t *testing.T) {
	signHex, err := privateKey.SignToHex([]byte(plaintext), crypto.SHA256)
	if err != nil {
		t.Error(err)
		return
	}
	sign, err2 := HexDecode(signHex)
	if err2 != nil {
		t.Error(err2)
		return
	}
	if !publicKey.Verify([]byte(plaintext), sign, crypto.SHA256) {
		t.Error("验签失败")
	}
}
