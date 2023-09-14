package snaper

import "testing"

func TestB2b(t *testing.T) {

	model := B2bModel{
		ClientKey:           "fill it",
		ClientSecret:        "fill it",
		PartnerID:           "fill it",
		UrlTokenB2b:         "fill it",
		RequestBodyTokenB2b: "fill it",
		UrlApi:              "fill it",
		HttpMethod:          "fill it",
		PrivateKey:          "fill it",
		BusinessType:        "fill it",
		RequestBody:         "fill it",
	}

	b2b := NewB2b(model)
	response, err := b2b.Hit()
	if err != nil {
		t.Error("ERROR ", *err)
		return
	}

	t.Log("SUCCESS ", response)
}

func TestB2b2c(t *testing.T) {

	model := B2b2cModel{
		ClientKey:             "fill it",
		ClientSecret:          "fill it",
		PartnerID:             "fill it",
		UrlTokenB2b:           "fill it",
		RequestBodyTokenB2b:   "fill it",
		UrlTokenB2b2c:         "fill it",
		RequestBodyTokenB2b2c: "fill it",
		UrlApi:                "fill it",
		HttpMethod:            "fill it",
		PrivateKey:            "fill it",
		BusinessType:          "fill it",
		RequestBody:           "fill it",
	}

	b2b2c := NewB2b2c(model)
	response, err := b2b2c.Hit()
	if err != nil {
		t.Error("ERROR ", *err)
		return
	}

	t.Log("SUCCESS ", response)
}
