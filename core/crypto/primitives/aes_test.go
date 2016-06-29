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
	"crypto/rand"
  "crypto/aes"
	"testing"
  "bytes"
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
      expectedLength, len(cipher) )
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
      expectedLength, len(cipher) )
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
  t.Log("bytes.Equal: ", bytes.Equal(iv1, iv2) )
  
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
    t.Fatalf("Error encrypting the message.", cipher)
  }
  
  expectedLength := aes.BlockSize + aes.BlockSize
  if len(cipher) != expectedLength {
    t.Fatalf("Cipher length incorrect: expected %d, got %d", expectedLength, len(cipher) )
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

func TestCBCEncrypt_DecryptManually(t *testing.T) {
  // Encrypt, then decrypt manually.
  
  // Probably not necessary
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

func TestCBCEncryptCBCPKCS7Decrypt(t *testing.T) {
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
  // checking cross-compatibility between PKCS7 and without  
  // Encrypt with CBCPKCS7Encrypt and Decrypt with CBCPKCS7Decrypt
  

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
