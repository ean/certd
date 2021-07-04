package client

import (
	"encoding/json"
	"fmt"
	"net/http"
)

func Get(domain string, serverAddress string) (*GetCertificateResponse, error) {
	client := http.Client{}
	req, err := http.NewRequest("POST", "https://"+serverAddress+":9443/get", nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	q.Set("domain", domain)
	req.URL.RawQuery = q.Encode()
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %s", res.Status)
	}
	resp := GetCertificateResponse{}
	if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
