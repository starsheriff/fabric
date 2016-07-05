/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package primitives

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestCBCEncrypt_EmptyText(t *testing.T) {
	// Encrypt an empty message. Mainly to document
	// a borderline case. Checking as well that the
	// cipher length is as expected.

	key := make([]byte, 32)
	rand.Reader.Read(key)

	t.Log("Generated key: ", key)

	var msg = []byte("")
	t.Log("Message length: ", len(msg))

	cipher, encErr := CBCEncrypt(key, msg)
	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	t.Log("Cipher length: ", len(cipher))

	// expected cipher length: 32
	// with padding, at least one block gets encrypted
	// the first block is the IV
	var expectedLength = aes.BlockSize + aes.BlockSize

	if len(cipher) != expectedLength {
		t.Fatalf("Cipher length is wrong. Expected %d, got %d",
			expectedLength, len(cipher))
	}
	t.Log("Cipher: ", cipher)
}

func TestCBCPKCS7Encrypt_EmptyText(t *testing.T) {
	// Encrypt an empty message. Mainly to document
	// a borderline case. Checking as well that the
	// cipher length is as expected.

	key := make([]byte, 32)
	rand.Reader.Read(key)

	t.Log("Generated key: ", key)

	var msg = []byte("")
	t.Log("Message length: ", len(msg))

	cipher, encErr := CBCPKCS7Encrypt(key, msg)
	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	t.Log("Cipher length: ", len(cipher))

	// expected cipher length: 32
	// with padding, at least one block gets encrypted
	// the first block is the IV
	var expectedLength = aes.BlockSize + aes.BlockSize

	if len(cipher) != expectedLength {
		t.Fatalf("Cipher length is wrong. Expected %d, got %d",
			expectedLength, len(cipher))
	}
	t.Log("Cipher: ", cipher)
}

func TestCBCPKCS7Encrypt_IVIsRandom(t *testing.T) {
	// Encrypt two times with same key. The first 16 bytes should be
	// different if IV is random.
	key := make([]byte, 32)
	rand.Reader.Read(key)
	t.Log("Key 1", key)

	var msg = []byte("a message to encrypt")

	cipher1, err := CBCPKCS7Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Error encrypting the message.")
	}

	// expecting a different IV if same message is encrypted with same key
	cipher2, err := CBCPKCS7Encrypt(key, msg)
	if err != nil {
		t.Fatalf("Error encrypting the message.")
	}

	iv1 := cipher1[:aes.BlockSize]
	iv2 := cipher2[:aes.BlockSize]

	t.Log("Cipher 1: ", iv1)
	t.Log("Cipher 2: ", iv2)
	t.Log("bytes.Equal: ", bytes.Equal(iv1, iv2))

	if bytes.Equal(iv1, iv2) {
		t.Fatal("Error: ciphers contain identical initialisation vectors.")
	}

}

func TestCBCPKCS7Encrypt_CipherLengthCorrect(t *testing.T) {
	// Check that the cipher lengths are as expected.
	key := make([]byte, 32)
	rand.Reader.Read(key)

	// length of message < aes.BlockSize (16 bytes)
	// --> expected cipher length = IV length (1 block) + 1 block message
	//     =
	var msg = []byte("short message")
	cipher, err := CBCPKCS7Encrypt(key, msg)
	if err != nil {
		t.Fatal("Error encrypting the message.", cipher)
	}

	expectedLength := aes.BlockSize + aes.BlockSize
	if len(cipher) != expectedLength {
		t.Fatalf("Cipher length incorrect: expected %d, got %d", expectedLength, len(cipher))
	}
}

func TestCBCEncryptCBCDecrypt_KeyMismatch(t *testing.T) {

	defer func() {
		recover()
	}()

	key := make([]byte, 32)
	rand.Reader.Read(key)

	decryptionKey := make([]byte, 32)
	copy(decryptionKey, key[:])
	decryptionKey[0] = key[0] + 1

	var msg = []byte("a message to be encrypted")

	encrypted, _ := CBCEncrypt(key, msg)
	decrypted, _ := CBCDecrypt(decryptionKey, encrypted)

	if string(msg[:]) == string(decrypted[:]) {
		t.Fatalf("Encryption->Decryption with different keys shouldn't return original message")
	}

}

func TestCBCEncrypt_IsDeterministic(t *testing.T) {
	// Check that the cipher is identical when encrypted with the same
	// key.

	// !!!
	// Cannot do yet because we cannot mock the IV :-/
}

func TestCBCEncrypt_RandomnessOneBitChange(t *testing.T) {
	// Change one bit (or byte?) in plain text. More than x% of cipher
	// should change as a result.

	// !!!
	// Cannot do yet because we cannot mock the IV
}

func TestCBCEncryptCBCDecrypt(t *testing.T) {
	// Encrypt with CBCEncrypt and Decrypt with CBCDecrypt

	key := make([]byte, 32)
	rand.Reader.Read(key)

	var msg = []byte("a 16 byte messag")

	encrypted, encErr := CBCEncrypt(key, msg)

	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	decrypted, dErr := CBCDecrypt(key, encrypted)

	if dErr != nil {
		t.Fatalf("Error encrypting message %v", dErr)
	}

	if string(msg[:]) != string(decrypted[:]) {
		t.Fatalf("Encryption->Decryption with same key should result in original message")
	}

}

// @jonathanlevi: this test fails, but I would expect it to run as a
// user.
func TestCBCEncryptCBCPKCS7Decrypt(t *testing.T) {
	// checking cross-compatibility between PKCS7 and without
	// Encrypt with CBCEncrypt and Decrypt with CBCPKCS7Decrypt

	key := make([]byte, 32)
	rand.Reader.Read(key)

	var msg = []byte("a 16 byte messag")

	encrypted, encErr := CBCEncrypt(key, msg)

	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	decrypted, dErr := CBCPKCS7Decrypt(key, encrypted)

	if dErr != nil {
		t.Fatalf("Error encrypting message %v", dErr)
	}

	if string(msg[:]) != string(decrypted[:]) {
		t.Fatalf("Encryption->Decryption with same key should result in original message")
	}

}

func TestCBCPKCS7EncryptCBCDecrypt(t *testing.T) {
	// checking cross-compatibility between PKCS7 and without
	// Encrypt with CBCEncrypt and Decrypt with CBCDecrypt

	key := make([]byte, 32)
	rand.Reader.Read(key)

	var msg = []byte("a 16 byte messag")

	encrypted, encErr := CBCPKCS7Encrypt(key, msg)

	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	decrypted, dErr := CBCDecrypt(key, encrypted)

	if dErr != nil {
		t.Fatalf("Error encrypting message %v", dErr)
	}

	if string(msg[:]) != string(decrypted[:]) {
		t.Log("msg: ", msg)
		t.Log("decrypted: ", decrypted)
		t.Fatalf("Encryption->Decryption with same key should result in original message")
	}

}

func TestCBCPKCS7EncryptCBCPKCS7Decrypt(t *testing.T) {
	// Encrypt with CBCPKCS7Encrypt and Decrypt with CBCPKCS7Decrypt
	// The intent is not to test the implementation of the aes standard
	// library but to verify the code around the calls to aes.

	key := make([]byte, 32)
	rand.Reader.Read(key)

	var msg = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := CBCPKCS7Encrypt(key, msg)

	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	decrypted, dErr := CBCPKCS7Decrypt(key, encrypted)

	if dErr != nil {
		t.Fatalf("Error encrypting message %v", dErr)
	}

	if string(msg[:]) != string(decrypted[:]) {
		t.Fatalf("Encryption->Decryption with same key should result in original message")
	}

}

func TestPKCS7Padding(t *testing.T) {
	// Verify the PKCS7 padding, plaintext version that is easier to read.

	// 0 byte message
	msg := []byte("")
	expected := []byte{16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16}
	result := PKCS7Padding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error: Expected ", expected, " but got ", result)
	}

	// 1 byte message
	msg = []byte("0")
	expected = []byte{'0', 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15}
	result = PKCS7Padding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error: Expected ", expected, " but got ", result)
	}

	// 2 byte message
	msg = []byte("01")
	expected = []byte{'0', '1', 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14}
	result = PKCS7Padding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error: Expected ", expected, " but got ", result)
	}

	// 3 to aes.BlockSize-1 byte messages
	for i := 3; i < aes.BlockSize; i++ {
		msg := []byte("0123456789ABCDEF")

		result := PKCS7Padding(msg[:i])

		padding := aes.BlockSize - i
		expectedPadding := bytes.Repeat([]byte{byte(padding)}, padding)
		expected = append(msg[:i], expectedPadding...)

		if !bytes.Equal(result, expected) {
			t.Fatal("Padding error: Expected ", expected, " but got ", result)
		}

	}

	// aes.BlockSize length message
	// !! needs to be modified for PR2093
	msg = bytes.Repeat([]byte{byte('x')}, aes.BlockSize)

	result = PKCS7Padding(msg)

	expectedPadding := bytes.Repeat([]byte{byte(aes.BlockSize)},
		aes.BlockSize)
	expected = append(msg, expectedPadding...)

	if len(result) != 2*aes.BlockSize {
		t.Fatal("Padding error: expected the length of the returned slice ",
			"to be 2 times aes.BlockSize")
	}

	if !bytes.Equal(expected, result) {
		t.Fatal("Padding error: Expected ", expected, " but got ", result)
	}

}

func TestPKCS7UnPadding(t *testing.T) {
	// 0 byte message
	expected := []byte("")
	msg := []byte{16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16,
		16, 16, 16, 16}

	result, _ := PKCS7UnPadding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error: Expected ", expected, " but got ", result)
	}

	// 1 byte message
	expected = []byte("0")
	msg = []byte{'0', 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15,
		15, 15, 15, 15}

	result, _ = PKCS7UnPadding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error: Expected ", expected, " but got ", result)
	}

	// 2 byte message
	expected = []byte("01")
	msg = []byte{'0', '1', 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14,
		14, 14, 14, 14}

	result, _ = PKCS7UnPadding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error: Expected ", expected, " but got ", result)
	}

	// 3 to aes.BlockSize-1 byte messages
	for i := 3; i < aes.BlockSize; i++ {
		base := []byte("0123456789ABCDEF")

		iPad := aes.BlockSize - i
		padding := bytes.Repeat([]byte{byte(iPad)}, iPad)
		msg = append(base[:i], padding...)

		expected := base[:i]
		result, _ := PKCS7UnPadding(msg)

		if !bytes.Equal(result, expected) {
			t.Fatal("UnPadding error: Expected ", expected, " but got ", result)
		}

	}

	// aes.BlockSize length message
	// !! needs to be modified for PR2093
	expected = bytes.Repeat([]byte{byte('x')}, aes.BlockSize)

	padding := bytes.Repeat([]byte{byte(aes.BlockSize)},
		aes.BlockSize)
	msg = append(expected, padding...)

	result, _ = PKCS7UnPadding(msg)

	if !bytes.Equal(expected, result) {
		t.Fatal("UnPadding error: Expected ", expected, " but got ", result)
	}

}

//
// @jonathanlevi: I'd remove everyting below this line for the PR. I
// just kept it for now in my fork.
//

// *********************************************************************
// Testing legacy code to proof refactoring with PR2051  did not change
// the behaviour.
// might be removed with a subsequent PR?!
// *********************************************************************

func TestPaddingsAreEqual(t *testing.T) {
	// Verify PR2051
	// Check that the implementations of paddings PKCS5 and 7 return
	// equal results.

	// check that paddings are equal up to aes.BlockSize
	for i := 0; i <= aes.BlockSize; i++ {
		msg := []byte("0123456789ABCDEF")
		t.Log("msg[:i] = ", msg[:i])
		msgPkcs5 := PKCS5PadLegacy(msg[:i])
		msgPkcs7 := PKCS7Padding(msg[:i])

		t.Log(msgPkcs5)
		t.Log(msgPkcs7)

		if !(bytes.Equal(msgPkcs5, msgPkcs7)) {
			t.Fatalf("Paddings are NOT equal for message length %d", i)
		}
	}
}

func TestCBCPKCS7EncryptCBCPKCS5Decrypt(t *testing.T) {
	// Encrypt with CBCPKCS7Encrypt and Decrypt with CBCDecrypt_Legacy

	key := make([]byte, 32)
	rand.Reader.Read(key)

	var msg = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := CBCPKCS7Encrypt(key, msg)

	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	decrypted, dErr := CBCDecryptLegacy(key, encrypted)

	if dErr != nil {
		t.Fatalf("Error encrypting message %v", dErr)
	}

	if string(msg[:]) != string(decrypted[:]) {
		t.Fatalf("Encryption->Decryption with same key should result in original message")
	}

}

func TestCBCPKCS5EncryptCBCPKCS7Decrypt(t *testing.T) {
	// Encrypt with CBCEncrypt_Legacy and Decrypt with CBCPKCS7Decrypt

	key := make([]byte, 32)
	rand.Reader.Read(key)

	var msg = []byte("a message with arbitrary length (42 bytes)")

	encrypted, encErr := CBCEncryptLegacy(key, msg)

	if encErr != nil {
		t.Fatalf("Error encrypting message %v", encErr)
	}

	decrypted, dErr := CBCPKCS7Decrypt(key, encrypted)

	if dErr != nil {
		t.Fatalf("Error encrypting message %v", dErr)
	}

	if string(msg[:]) != string(decrypted[:]) {
		t.Fatalf("Encryption->Decryption with same key should result in original message")
	}

}

// *********************************************************************
// Legacy code to proof refactoring with PR2051  did not change
// the behaviour.
// might be removed with a subsequent PR?!
// *********************************************************************

// PKCS5Pad adds a PKCS5 padding.
//
func PKCS5PadLegacy(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, pad...)
}

// PKCS5Unpad removes a PKCS5 padding.
//
func PKCS5UnpadLegacy(src []byte) []byte {
	len := len(src)
	unpad := int(src[len-1])
	return src[:(len - unpad)]
}

// CBCEncrypt performs an AES CBC encryption.
//
func CBCEncryptLegacy(key, s []byte) ([]byte, error) {
	src := PKCS5PadLegacy(s)

	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext length is not a multiple of the block size")
	}

	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	enc := make([]byte, aes.BlockSize+len(src))
	iv := enc[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(blk, iv)
	mode.CryptBlocks(enc[aes.BlockSize:], src)

	return enc, nil
}

// CBCDecrypt performs an AES CBC decryption.
//
func CBCDecryptLegacy(key, src []byte) ([]byte, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(src) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := src[:aes.BlockSize]
	src = src[aes.BlockSize:]

	if len(src)%aes.BlockSize != 0 {
		return nil, errors.New("ciphertext length is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(blk, iv)
	mode.CryptBlocks(src, src)

	return PKCS5UnpadLegacy(src), nil
}
