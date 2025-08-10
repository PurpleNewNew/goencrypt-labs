
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB
var privateKey *rsa.PrivateKey

// --- Structs ---

type FormData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type DesRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type AesRsaRequest struct {
	EncryptedKey  string `json:"encryptedKey"`
	EncryptedData string `json:"encryptedData"`
}

type AesRandomKeyRequest struct {
	EncryptedKey  string `json:"encryptedKey"`
	EncryptedData string `json:"encryptedData"`
}

type SignDataRequest struct {
	Username  string `json:"username"`
	Password  string `json:"password"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
}

type NoRepeaterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Random   string `json:"random"`
}

type AesServerResponse struct {
	Key string `json:"key"`
	Iv  string `json:"iv"`
}

type SignDataServerResponse struct {
	SecretKey string `json:"secretKey"`
}

type Response struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// --- Main Function ---

func main() {
	// --- Database Setup ---
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Create users table
	_, err = db.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE,
			email TEXT UNIQUE,
			password TEXT,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Create requests table
	_, err = db.Exec(`
		CREATE TABLE requests (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			requestID TEXT UNIQUE,
			timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	// Insert default admin user
	_, err = db.Exec("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", "admin", "admin@example.com", "e10adc3949ba59abbe56e057f20f883e")
	if err != nil {
		log.Fatal(err)
	}

	// --- RSA Key Setup ---
	loadPrivateKey()

	// --- HTTP Server Setup ---
	fs := http.FileServer(http.Dir("static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/index.html")
	})
	http.HandleFunc("/easy.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/easy.html")
	})
	http.HandleFunc("/hard.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/hard.html")
	})
	http.HandleFunc("/success.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "static/success.html")
	})

	// API Handlers
	http.HandleFunc("/encrypt/aes", aesHandler)
	http.HandleFunc("/encrypt/des", desHandler)
	http.HandleFunc("/encrypt/rsa", rsaHandler)
	http.HandleFunc("/encrypt/aesserver", aesserverHandler)
	http.HandleFunc("/encrypt/aesrsa", aesrsaHandler)
	http.HandleFunc("/encrypt/signdata", signdataHandler)
	http.HandleFunc("/encrypt/signdataserver", signdataserverHandler)
	http.HandleFunc("/encrypt/norepeater", norepeaterHandler)
	http.HandleFunc("/encrypt/aes_random_key", aesRandomKeyHandler)
	http.HandleFunc("/encrypt/get-public-key", getPublicKeyHandler)

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

// --- AES Handler ---

func aesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Failed to parse form"})
		return
	}

	encryptedData := r.FormValue("encryptedData")
	if encryptedData == "" {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "No encrypted data"})
		return
	}

	decryptedData, err := decryptAESWithHardcodedKey([]byte(encryptedData))
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Decryption failed"})
		return
	}

	var formData FormData
	if err := json.Unmarshal(decryptedData, &formData); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid decrypted data"})
		return
	}

	// Database verification
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", formData.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(formData.Password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

func decryptAESWithHardcodedKey(encryptedData []byte) ([]byte, error) {
	key := []byte("1234567890123456")
	iv := []byte("1234567890123456")
	return decryptAES(encryptedData, key, iv)
}

func decryptAES(encryptedData []byte, key, iv []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(string(encryptedData))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return pkcs7Unpad(decrypted)
}

// --- DES Handler ---

func desHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req DesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid request"})
		return
	}

	key := []byte(padString(req.Username, 8, "6"))
	iv := []byte("9999" + req.Username[:4])

	decryptedPassword, err := decryptDES(req.Password, key, iv)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Decryption failed"})
		return
	}

	// Database verification
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write(decryptedPassword)
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

func decryptDES(encryptedData string, key, iv []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}

	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%des.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(ciphertext))
	mode.CryptBlocks(decrypted, ciphertext)

	return pkcs7Unpad(decrypted)
}

// --- RSA Handler ---

func rsaHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Failed to parse form"})
		return
	}

	data := r.FormValue("data")
	if data == "" {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "No data received"})
		return
	}

	decryptedData, err := rsaDecrypt(data)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Data decryption failed"})
		return
	}

	var formData FormData
	if err := json.Unmarshal(decryptedData, &formData); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Missing username or password"})
		return
	}

	// Database verification
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", formData.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(formData.Password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

func rsaDecrypt(encryptedData string) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, decodedData)
}

func loadPrivateKey() {
	pemData := `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDRvA7giwinEkaTYllDYCkzujviNH+up0XAKXQot8RixKGpB7nr
8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlMDSj92Mr3xSaJcshZU8kfj325
L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3CbocDbsNeCwNpRxwjIdQIDAQAB
AoGAMek68RylFn025mQFMg90PqcXESHFMN8FrlEvH3F7/rUkc4EvMYKRf1CFsWi5
Cdj1ofyidIibiOaT7kEnS9CK//SmY+1628/eyngOvOR9ADsHN/JRlJ3dHathcBrr
1GENlCB9EmN+Fzhh7vEC2RUPrkkHCYGU2j+9rkzHUCXxLpECQQD5jgm9K7bvsOzM
82v6avdNFAV/9ILdple1xlCfcEuWgnRztxTS6fbVguDCkB95yQq/WT2XzuohUMSG
0uGGemlbAkEA1ya+aG8bRNlEC4yGiROSWZOiFBtiUhMyDGQ4E/FUifNdZSft5jSE
gqUZZYJNchyKSXWtFKyclvJjcnflKxBubwJAT7eexs4bDvA+hK3RtVnMC9Q0eY5a
64ECja9++598leSwXHKEdWeFkOjQ8XXmiBm/lCZmtYLEacYKMWNV5YZe9wJAMYM/
CnWXRu7hE+9Q/ra8VVT+VbY/mDfGqsddiGlfVSfmdGMOAo5PeGlaQNwNypb61BD6
telLWAmMDUm+OXzcjQJBAJGn+vI0JV7OI0m4QpSucn/rJ9pAYJG4HE/MOQcgHog0
AeussmDIlr+wqWr+iJxYfJHc8ikTRSeTgqavruZs2Hg=
-----END RSA PRIVATE KEY-----
`
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		log.Fatal("failed to parse PEM block containing the private key")
	}

	var err error
	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatal("failed to parse DER encoded private key: " + err.Error())
	}
}

// --- AES Server Handler ---

func aesserverHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	response := AesServerResponse{
		Key: "1234567890123456",
		Iv:  "1234567890123456",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// --- AES+RSA Handler ---

func aesrsaHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req AesRsaRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid request"})
		return
	}

	decryptedKeyBase64, err := rsaDecrypt(req.EncryptedKey)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Key decryption failed"})
		return
	}

	decryptedKey, err := base64.StdEncoding.DecodeString(string(decryptedKeyBase64))
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Failed to decode base64 key"})
		return
	}

	iv := decryptedKey // In this specific case, the key is also used as the IV

	decryptedData, err := decryptAES([]byte(req.EncryptedData), decryptedKey, iv)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Data decryption failed"})
		return
	}

	var formData FormData
	if err := json.Unmarshal(decryptedData, &formData); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid decrypted data"})
		return
	}

	// Database verification
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", formData.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(formData.Password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

// --- Sign Data Handler ---

func signdataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req SignDataRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid request"})
		return
	}

	// Check timestamp
	if time.Now().Unix()-req.Timestamp > 500 {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Request timeout"})
		return
	}

	// Verify signature
	secretKey := []byte("be56e057f20f883e")
	dataToSign := req.Username + req.Password + req.Nonce + strconv.FormatInt(req.Timestamp, 10)
	h := hmac.New(sha256.New, secretKey)
	h.Write([]byte(dataToSign))
	serverSignature := hex.EncodeToString(h.Sum(nil))

	if !hmac.Equal([]byte(serverSignature), []byte(req.Signature)) {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Signature mismatch - data tampered"})
		return
	}

	// Database verification
	var dbPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(req.Password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

// --- Sign Data Server Handler ---

func signdataserverHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	response := SignDataServerResponse{
		SecretKey: "be56e057f20f883e",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// --- No Repeater Handler ---

func norepeaterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req NoRepeaterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "数据不完整"})
		return
	}

	// Decrypt random
	decryptedTimestamp, err := rsaDecrypt(req.Random)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "随机值解密失败"})
		return
	}

	timestamp, err := strconv.ParseInt(string(decryptedTimestamp), 10, 64)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid timestamp"})
		return
	}

	// Check timestamp window
	if time.Now().UnixMilli()-timestamp > 3000 {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "No Repeater"})
		return
	}

	// Check requestID
	requestID := fmt.Sprintf("%x", sha256.Sum256([]byte(req.Username+req.Password+strconv.FormatInt(timestamp, 10)+strconv.FormatInt(time.Now().UnixMilli(), 10))))
	var existingRequestID string
	err = db.QueryRow("SELECT requestID FROM requests WHERE requestID = ?", requestID).Scan(&existingRequestID)
	if err != nil && err != sql.ErrNoRows {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		return
	}
	if existingRequestID != "" {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "requestID exist"})
		return
	}

	// Insert requestID
	_, err = db.Exec("INSERT INTO requests (requestID) VALUES (?)", requestID)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		return
	}

	// Database verification
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", req.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(req.Password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true, Error: "Login Success"})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

// --- AES Random Key Handler ---

func aesRandomKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	var req AesRandomKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid request"})
		return
	}

	// Decrypt the AES key received from the client
	decryptedKeyBase64, err := rsaDecrypt(req.EncryptedKey)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Key decryption failed"})
		return
	}

	decryptedKey, err := base64.StdEncoding.DecodeString(string(decryptedKeyBase64))
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Failed to decode base64 key"})
		return
	}

	iv := decryptedKey // The key is also used as the IV in the client-side logic

	decryptedData, err := decryptAES([]byte(req.EncryptedData), decryptedKey, iv)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Data decryption failed"})
		return
	}

	var formData FormData
	if err := json.Unmarshal(decryptedData, &formData); err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid decrypted data"})
		return
	}

	// Database verification
	var dbPassword string
	err = db.QueryRow("SELECT password FROM users WHERE username = ?", formData.Username).Scan(&dbPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
		} else {
			json.NewEncoder(w).Encode(Response{Success: false, Error: "Database error"})
		}
		return
	}

	hasher := md5.New()
	hasher.Write([]byte(formData.Password))
	md5Password := hex.EncodeToString(hasher.Sum(nil))

	if dbPassword == md5Password {
		json.NewEncoder(w).Encode(Response{Success: true})
	} else {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Invalid username or password"})
	}
}

// --- Get Public Key Handler ---

func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		json.NewEncoder(w).Encode(Response{Success: false, Error: "Failed to marshal public key"})
		return
	}

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	response := map[string]string{"publicKey": string(pubKeyPem)}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}


// --- Utility Functions ---

func padString(input string, length int, padChar string) string {
	if len(input) >= length {
		return input[:length]
	}
	return input + strings.Repeat(padChar, length-len(input))
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: data is empty")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("pkcs7: padding is invalid")
	}
	pad := data[len(data)-padding:]
	for i := 0; i < padding; i++ {
		if pad[i] != byte(padding) {
			return nil, errors.New("pkcs7: padding is invalid")
		}
	}
	return data[:len(data)-padding], nil
}
