package oktaconnector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/okta/okta-sdk-golang/v8/okta"
)

type APIKey struct {
	APIKey string `json:"aPIKey" yaml:"APIKey"`
}

type UserDefinedCredentials struct {
	APIKey APIKey `json:"aPIKey" yaml:"APIKey"`
}

type OktaConnector struct {
	AppURL                 string                  `json:"appURL" yaml:"appURL"`
	AppPort                int                     `json:"appPort" yaml:"port"`
	Ipv4Address            string                  `json:"ipv4Address" yaml:"ipv4Address"`
	Ipv6Address            string                  `json:"ipv6Address" yaml:"ipv6Address"`
	UserDefinedCredentials *UserDefinedCredentials `json:"userDefinedCredentials" yaml:"userDefinedCredentials"`
	Client                 *okta.APIClient
}

func (thisObj *OktaConnector) Validate() (bool, error) {
	err := thisObj.createNewClient()
	if err != nil {
		return false, err
	}

	_, response, err := thisObj.Client.UserAPI.GetUser(context.Background(), "me").Execute()
	if err != nil {
		return false, thisObj.getOktaErrorMsg(err, response)
	}

	return true, nil
}

func (thisObj *OktaConnector) createNewClient() error {
	if strings.Contains(thisObj.AppURL, "-admin") {
		return errors.New("your Okta domain should not contain -admin. You can copy your domain from the Okta Developer Console. Follow these instructions to find it: https://developer.okta.com/docs/guides/find-your-domain/overview")
	}

	err := thisObj.UserDefinedCredentials.APIKey.ValidateAttributes()
	if err != "" {
		return errors.New(err)
	}

	if thisObj.Client == nil {
		config, err := okta.NewConfiguration(
			okta.WithOrgUrl(thisObj.AppURL),
			okta.WithToken(thisObj.UserDefinedCredentials.APIKey.APIKey),
		)
		if err != nil {
			return err
		}
		orgURL, err := url.Parse(thisObj.AppURL)
		if err != nil {
			return err
		}
		config.Host = orgURL.Host
		thisObj.Client = okta.NewAPIClient(config)
	}

	return nil
}

func (thisObj *OktaConnector) getOktaErrorMsg(err error, response *okta.APIResponse) error {
	if err != nil {
		if strings.Contains(err.Error(), "no such host") {
			return errors.New("Invalid AppURL")
		}
		if response != nil && response.Response != nil && response.StatusCode == http.StatusUnauthorized {
			return errors.New("Invalid URL/APIKey. Please check.")
		}
		return err
	}
	return nil
}

func (apikey *APIKey) ValidateAttributes() string {
	var emptyAttributes []string
	errorResultStr := ""
	if apikey.APIKey == "" {
		emptyAttributes = append(emptyAttributes, "APIKey")
	}
	if len(emptyAttributes) > 0 {
		errorResultStr = fmt.Sprintf("Invalid Credentials: %s", strings.Join(emptyAttributes, ", ")+" is empty")
	}
	return errorResultStr
}

// INFO : You can implement your own implementation for the class
