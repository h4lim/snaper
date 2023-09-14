package snaper

import (
	"errors"
	"github.com/google/uuid"
	party "github.com/h4lim/client-party"
)

type clientPartyB2bContext struct {
	b2bModel B2bModel
}

type B2bClientPartyHandler interface {
	HitToken(timestamp string, signature string, requestBody string) (*party.Response, *error)
	HitEndpoint(authB2b string, timestamp string, signature string) (*party.Response, *error)
}

func NewClientPartyB2b(b2bModel B2bModel) B2bClientPartyHandler {
	return clientPartyB2bContext{b2bModel: b2bModel}
}

func (c clientPartyB2bContext) HitToken(timestamp string, signature string, requestBody string) (*party.Response, *error) {

	mapHeader := make(map[string]string)
	mapHeader["X-CLIENT-KEY"] = c.b2bModel.ClientKey
	mapHeader["X-TIMESTAMP"] = timestamp
	mapHeader["X-SIGNATURE"] = signature

	cpBuilder := party.NewClientParty(party.MethodPost, c.b2bModel.UrlTokenB2b).
		SetRequestBodyStr(requestBody).
		SetHeader(party.MIMEJSON, mapHeader)

	response, err := cpBuilder.HitClient()
	if err != nil {
		return nil, err
	}

	if response.HttpCode != 200 {
		newError := errors.New(response.ResponseBody)
		return nil, &newError
	}

	return response, nil
}

func (c clientPartyB2bContext) HitEndpoint(authB2b string, timestamp string, signature string) (*party.Response, *error) {

	mapHeader := make(map[string]string)
	mapHeader["Authorization"] = "Bearer " + authB2b
	mapHeader["X-CLIENT-KEY"] = c.b2bModel.ClientKey
	mapHeader["X-TIMESTAMP"] = timestamp
	mapHeader["X-SIGNATURE"] = signature
	mapHeader["X-PARTNER-ID"] = c.b2bModel.PartnerID
	mapHeader["X-EXTERNAL-ID"] = uuid.New().String()
	mapHeader["CHANNEL-ID"] = "8888"
	mapHeader["X-IP-ADDRESS"] = "123123"

	response, err := party.NewClientParty(c.b2bModel.HttpMethod, c.b2bModel.UrlApi).
		SetHeader(party.MIMEJSON, mapHeader).SetRequestBodyStr(c.b2bModel.RequestBody).HitClient()
	if err != nil {
		return nil, err
	}

	if response.HttpCode != 200 {
		newError := errors.New(response.ResponseBody)
		return nil, &newError
	}

	return response, nil
}
