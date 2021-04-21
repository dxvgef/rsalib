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
	privateBase64File = "./private_base64.key"
	privateHexFile    = "./private_hex.key"
	publicBase64File  = "./public_base64.key"
	publicHexFile     = "./public_hex.key"
	plaintext         = "abc"
)

// 测试前准备
func TestMain(m *testing.M) {
	// 开始运行测试用例
	m.Run()
	os.Exit(0)
}

// 测试入口
func TestAll(t *testing.T) {
	// 私钥转换
	t.Run("TestPrivateKeyNew", TestPrivateKey_New)
	t.Run("TestPrivateKey_GetPublicKey", TestPrivateKey_GetPublicKey)

	t.Run("TestPrivateKey_Raw", TestPrivateKey_Raw)
	t.Run("TestPrivateKey_RawBytes", TestPrivateKey_RawBytes)
	t.Run("TestPrivateKey_Base64", TestPrivateKey_Base64)
	t.Run("TestPrivateKey_Base64File", TestPrivateKey_Base64File)
	t.Run("TestPrivateKey_Hex", TestPrivateKey_Hex)
	t.Run("TestPrivateKey_File", TestPrivateKey_HexFile)

	t.Run("TestPublicKey_Raw", TestPublicKey_Raw)
	t.Run("TestPublicKey_RawBytes", TestPublicKey_RawBytes)
	t.Run("TestPublicKey_Base64", TestPublicKey_Base64)
	t.Run("TestPublicKey_Base64File", TestPublicKey_Base64File)
	t.Run("TestPublicKey_Hex", TestPublicKey_Hex)
	t.Run("TestPublicKey_HexFile", TestPublicKey_HexFile)

	t.Run("TestSign", TestSign)
	t.Run("TestSignBase64", TestSignBase64)
	t.Run("TestSignHex", TestSignHex)

	t.Run("TestEncrypt", TestEncrypt)
	t.Run("TestEncryptBase64", TestEncryptBase64)
	t.Run("TestEncryptHex", TestEncryptHex)
}

func TestPrivateKey_New(t *testing.T) {
	err := privateKey.New(2048)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_Raw(t *testing.T) {
	err := privateKey.FromRaw(privateKey.ToRaw())
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_RawBytes(t *testing.T) {
	src, err := privateKey.ToRawBytes(PKCS1)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromRawBytes(src)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_Base64(t *testing.T) {
	src, err := privateKey.ToBase64(base64.RawURLEncoding, PKCS1)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromBase64(base64.RawURLEncoding, src)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_Base64File(t *testing.T) {
	err := privateKey.ToBase64File(base64.RawURLEncoding, PKCS1, privateBase64File, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromBase64File(base64.RawURLEncoding, privateBase64File)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_Hex(t *testing.T) {
	src, err := privateKey.ToHex(PKCS1)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromHex(src)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_HexFile(t *testing.T) {
	err := privateKey.ToHexFile(PKCS1, privateHexFile, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	err = privateKey.FromHexFile(privateHexFile)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPrivateKey_GetPublicKey(t *testing.T) {
	publicKey = privateKey.GetPublicKey()
}

func TestPublicKey_Raw(t *testing.T) {
	publicKey.FromRaw(publicKey.ToRaw())
}

func TestPublicKey_RawBytes(t *testing.T) {
	data := publicKey.ToRawBytes()
	err := publicKey.FromRawBytes(data)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPublicKey_Base64(t *testing.T) {
	data, err := publicKey.ToBase64(base64.RawURLEncoding)
	if err != nil {
		t.Error(err)
		return
	}
	err = publicKey.FromBase64(base64.RawURLEncoding, data)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPublicKey_Base64File(t *testing.T) {
	err := publicKey.ToBase64File(base64.RawURLEncoding, publicBase64File, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	err = publicKey.FromBase64File(base64.RawURLEncoding, publicBase64File)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPublicKey_Hex(t *testing.T) {
	data, err := publicKey.ToHex()
	if err != nil {
		t.Error(err)
		return
	}
	err = publicKey.FromHex(data)
	if err != nil {
		t.Error(err)
		return
	}
}

func TestPublicKey_HexFile(t *testing.T) {
	err := publicKey.ToHexFile(publicHexFile, 0600)
	if err != nil {
		t.Error(err)
		return
	}
	err = publicKey.FromHexFile(publicHexFile)
	if err != nil {
		t.Error(err)
		return
	}
}

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

func TestEncryptBase64(t *testing.T) {
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

func TestEncryptHex(t *testing.T) {
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

func TestSign(t *testing.T) {
	sign, err := privateKey.Sign([]byte(plaintext), crypto.SHA256)
	if err != nil {
		t.Error(err)
		return
	}
	if !publicKey.Verify([]byte(plaintext), sign, crypto.SHA256) {
		t.Error("验签失败")
		return
	}
}

func TestSignBase64(t *testing.T) {
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
		return
	}
}

func TestSignHex(t *testing.T) {
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
		return
	}
}
