package snaper

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	songwriter "github.com/json-iterator/go"
	"net/url"
	"regexp"
	"strings"
)

func decodePrivateKey(key string) (*rsa.PrivateKey, *error) {

	privateKey := removeBetweenChar(key)
	var formattedPrivateKey string
	if strings.Contains(privateKey, "\n") {
		formattedPrivateKey = privateKey
	} else {
		formattedPrivateKey = insertValidFormat(privateKey, 64)
	}

	var bytePrivateKey []byte
	if strings.HasPrefix(formattedPrivateKey, "-----") {
		bytePrivateKey = []byte(formattedPrivateKey)
	} else {
		bytePrivateKey = []byte("-----BEGIN RSA PRIVATE KEY-----\n" + formattedPrivateKey + "\n-----END RSA PRIVATE KEY-----")
	}

	pemPrivateKey, _ := pem.Decode(bytePrivateKey)
	if pemPrivateKey == nil {
		err := errors.New("RSA private key can't read")
		return nil, &err
	}

	pkcs1PrivateKey, err := x509.ParsePKCS1PrivateKey(pemPrivateKey.Bytes)
	if err != nil {
		return nil, &err
	}

	return pkcs1PrivateKey, nil
}

func createSignatureToken(clientKey string, timestamp string, privateKey rsa.PrivateKey) (*string, *error) {

	formula := clientKey + "|" + timestamp
	digest := sha256.Sum256([]byte(formula))

	byteSignature, err := rsa.SignPKCS1v15(rand.Reader, &privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return nil, &err
	}

	stringEncode := base64.StdEncoding.EncodeToString(byteSignature)

	return &stringEncode, nil
}

func minifyPayload(jsonString string) (*string, *error) {
	if jsonString == "" {
		minifiedJSON, err := songwriter.MarshalToString(jsonString)
		if err != nil {
			return nil, &err
		}

		return &minifiedJSON, nil
	}

	minifiedJSON := &bytes.Buffer{}
	if err := json.Compact(minifiedJSON, []byte(jsonString)); err != nil {
		return nil, &err
	}

	strJson := minifiedJSON.String()

	return &strJson, nil
}

func createHash256(strJson string, httpMethod string) string {

	if strings.ToUpper(httpMethod) == "GET" {
		strJson = ""
	}

	hasher := sha256.New()
	hasher.Write([]byte(strJson))
	hashSum := hasher.Sum(nil)
	encodeString := hex.EncodeToString(hashSum)

	return strings.ToLower(encodeString)
}

func createSignaturePayload(clientSecret string,
	httpMethod string, url string, accessToken string, encodeRequestBody string, timestamp string) string {

	hasher := hmac.New(sha512.New, []byte(clientSecret))
	formula := strings.ToUpper(httpMethod) + ":" +
		url + ":" + accessToken + ":" +
		encodeRequestBody + ":" + timestamp

	hasher.Write([]byte(formula))
	digest := hasher.Sum(nil)

	return base64.StdEncoding.EncodeToString(digest)
}

func removeBetweenChar(inputString string) string {
	pattern := `-(.*?)-`
	regex := regexp.MustCompile(pattern)
	matches := regex.FindAllStringSubmatch(inputString, -1)
	for _, match := range matches {
		inputString = strings.Replace(inputString, match[0], "", 1)
	}

	return inputString
}

func removeQueryParam(originUrl string) (*string, *error) {
	u, err := url.Parse(originUrl)
	if err != nil {
		return nil, &err
	}

	resultUrl := u.Host + u.Path
	return &resultUrl, nil
}

func getRelativePath(fullUrl string) (*string, *error) {

	u, err := url.Parse(fullUrl)
	if err != nil {
		return nil, &err
	}

	resultUrl := u.Path
	return &resultUrl, nil
}

func getToken(jsonString string) (*string, *error) {

	var data map[string]interface{}
	err := json.Unmarshal([]byte(jsonString), &data)
	if err != nil {
		return nil, &err
	}

	value, ok := data["accessToken"].(string)
	if !ok {
		newError := errors.New("key not found or not a string")
		return nil, &newError
	}

	return &value, nil
}

func insertValidFormat(s string, n int) string {

	var buffer bytes.Buffer
	var n1 = n - 1
	var l1 = len(s) - 1
	for i, r := range s {
		buffer.WriteRune(r)
		if i%n == n1 && i != l1 {
			buffer.WriteRune('\n')
		}
	}

	return buffer.String()
}
