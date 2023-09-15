package snaper

import (
	"github.com/google/uuid"
	party "github.com/h4lim/client-party"
)

type clientPartyB2b2cContext struct {
	b2b2cModel B2b2cModel
}

type B2b2ClientPartyHandler interface {
	HitToken(timestamp string, signature string, requestBody string) (*party.Response, *error)
	HitEndpoint(authB2b string, authCustomer string, timestamp string, signature string) (*party.Response, *error)
}

func NewClientPartyB2b2c(b2b2cModel B2b2cModel) B2b2ClientPartyHandler {
	return clientPartyB2b2cContext{b2b2cModel: b2b2cModel}
}

func (c clientPartyB2b2cContext) HitToken(timestamp string, signature string, requestBody string) (*party.Response, *error) {

	mapHeader := make(map[string]string)
	mapHeader["X-CLIENT-KEY"] = c.b2b2cModel.ClientKey
	mapHeader["X-TIMESTAMP"] = timestamp
	mapHeader["X-SIGNATURE"] = signature

	cpBuilder := party.NewClientParty(party.MethodPost, c.b2b2cModel.UrlTokenB2b2c).
		SetRequestBodyStr(requestBody).
		SetHeader(party.MIMEJSON, mapHeader)

	response, err := cpBuilder.HitClient()
	if err != nil {
		return nil, err
	}

	return response, nil
}

func (c clientPartyB2b2cContext) HitEndpoint(authB2b string, authCustomer string, timestamp string, signature string) (*party.Response, *error) {

	mapHeader := make(map[string]string)
	mapHeader["Authorization"] = "Bearer " + authB2b
	mapHeader["X-CLIENT-KEY"] = c.b2b2cModel.ClientKey
	mapHeader["X-TIMESTAMP"] = timestamp
	mapHeader["X-SIGNATURE"] = signature
	mapHeader["X-PARTNER-ID"] = c.b2b2cModel.PartnerID
	mapHeader["X-EXTERNAL-ID"] = uuid.New().String()
	mapHeader["CHANNEL-ID"] = "8888"
	mapHeader["X-IP-ADDRESS"] = "123123"
	mapHeader["Authorization-Customer"] = "Bearer " + authCustomer

	response, err := party.NewClientParty(c.b2b2cModel.HttpMethod, c.b2b2cModel.UrlApi).
		SetHeader(party.MIMEJSON, mapHeader).SetRequestBodyStr(c.b2b2cModel.RequestBody).HitClient()
	if err != nil {
		return nil, err
	}

	return response, nil
}
