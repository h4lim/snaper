package snaper

import (
	party "github.com/h4lim/client-party"
	"time"
)

type B2b2cModel struct {
	ClientKey             string
	ClientSecret          string
	PartnerID             string
	UrlTokenB2b           string
	RequestBodyTokenB2b   string
	UrlTokenB2b2c         string
	RequestBodyTokenB2b2c string
	UrlApi                string
	HttpMethod            string
	PrivateKey            string
	BusinessType          string
	RequestBody           string
}

type b2b2cConfigContext struct {
	b2b2cModel B2b2cModel
}

type B2b2cHandler interface {
	Hit() (*party.Response, *error)
}

func NewB2b2c(b2b2cModel B2b2cModel) B2bHandler {
	return b2b2cConfigContext{b2b2cModel: b2b2cModel}
}

func (b b2b2cConfigContext) Hit() (*party.Response, *error) {

	rsaPrivateKey, err := DecodePrivateKey(b.b2b2cModel.PrivateKey)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now().Format(time.RFC3339)
	signatureToken, err := CreateSignatureToken(b.b2b2cModel.ClientKey, timestamp, *rsaPrivateKey)
	if err != nil {
		return nil, err
	}

	b2bModel := B2bModel{
		ClientKey:           b.b2b2cModel.ClientKey,
		ClientSecret:        b.b2b2cModel.ClientSecret,
		PartnerID:           b.b2b2cModel.PartnerID,
		UrlTokenB2b:         b.b2b2cModel.UrlTokenB2b,
		RequestBodyTokenB2b: b.b2b2cModel.RequestBodyTokenB2b,
		UrlApi:              b.b2b2cModel.UrlApi,
		HttpMethod:          b.b2b2cModel.HttpMethod,
		PrivateKey:          b.b2b2cModel.PrivateKey,
		BusinessType:        b.b2b2cModel.BusinessType,
		RequestBody:         b.b2b2cModel.RequestBody,
	}

	client := NewClientPartyB2b(b2bModel)
	client.HitToken(timestamp, *signatureToken, b.b2b2cModel.RequestBodyTokenB2b)
	responseToken, err := client.HitToken(timestamp, *signatureToken, b.b2b2cModel.RequestBodyTokenB2b)
	if err != nil {
		return nil, err
	}

	if responseToken.HttpCode != 200 {
		return responseToken, nil
	}

	tokenB2b, err := GetToken(responseToken.ResponseBody)
	if err != nil {
		return nil, err
	}

	clientB2b2c := NewClientPartyB2b2c(b.b2b2cModel)
	responseTokenB2b2c, err := clientB2b2c.HitToken(timestamp, *signatureToken, b.b2b2cModel.RequestBodyTokenB2b2c)
	if err != nil {
		return nil, err
	}

	tokenB2b2c, err := GetToken(responseTokenB2b2c.ResponseBody)
	if err != nil {
		return nil, err
	}

	relativePath, err := GetRelativePath(b.b2b2cModel.UrlApi)
	if err != nil {
		return nil, err
	}

	minify, err := MinifyPayload(b.b2b2cModel.RequestBody)
	if err != nil {
		return nil, err
	}

	encodeRequestBody := CreateHash256(*minify, b.b2b2cModel.HttpMethod)
	signaturePayload := CreateSignaturePayload(b.b2b2cModel.ClientSecret, b.b2b2cModel.HttpMethod,
		*relativePath, *tokenB2b2c, encodeRequestBody, timestamp)
	responseEndpoint, err := clientB2b2c.HitEndpoint(*tokenB2b, *tokenB2b2c, timestamp, signaturePayload)
	if err != nil {
		return nil, err
	}

	return responseEndpoint, nil
}
