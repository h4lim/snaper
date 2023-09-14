package snaper

import (
	party "github.com/h4lim/client-party"
	"time"
)

type B2bModel struct {
	ClientKey           string
	ClientSecret        string
	PartnerID           string
	UrlTokenB2b         string
	RequestBodyTokenB2b string
	UrlApi              string
	HttpMethod          string
	PrivateKey          string
	BusinessType        string
	RequestBody         string
}

type b2bConfigContext struct {
	b2bModel B2bModel
}

type B2bHandler interface {
	Hit() (*party.Response, *error)
}

func NewB2b(b2bModel B2bModel) B2bHandler {
	return b2bConfigContext{b2bModel: b2bModel}
}

func (b b2bConfigContext) Hit() (*party.Response, *error) {

	rsaPrivateKey, err := DecodePrivateKey(b.b2bModel.PrivateKey)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Format(time.RFC3339)
	signatureToken, err := CreateSignatureToken(b.b2bModel.ClientKey, timestamp, *rsaPrivateKey)
	if err != nil {
		return nil, err
	}

	client := NewClientPartyB2b(b.b2bModel)
	responseToken, err := client.HitToken(timestamp, *signatureToken, b.b2bModel.RequestBodyTokenB2b)
	if err != nil {
		return nil, err
	}

	token, err := GetToken(responseToken.ResponseBody)
	if err != nil {
		return nil, err
	}

	relativePath, err := GetRelativePath(b.b2bModel.UrlApi)
	if err != nil {
		return nil, err
	}

	minify, err := MinifyPayload(b.b2bModel.RequestBody)
	if err != nil {
		return nil, err
	}

	encodeRequestBody := CreateHash256(*minify, b.b2bModel.HttpMethod)
	signaturePayload := CreateSignaturePayload(b.b2bModel.ClientSecret, b.b2bModel.HttpMethod,
		*relativePath, *token, encodeRequestBody, timestamp)

	responseEndpoint, err := client.HitEndpoint(*token, timestamp, signaturePayload)
	if err != nil {
		return nil, err
	}

	return responseEndpoint, nil
}
