package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type _wos_login struct {
	Ticket    string `json:"ticket"`
	CompanyID string `json:"company_id"`
	UAType    int    `json:"ua_type"`
}
type _wos_stat struct {
	Code int `json:"code"`
	Data struct {
		Acclines []struct {
			IP        string   `json:"ip"`
			Name      string   `json:"name"`
			NatIPs    []string `json:"nat_ips"`
			Port      int      `json:"port"`
			Algorithm string   `json:"ss_algorithm"`
			Password  string   `json:"ss_password"`
		} `json:"acclines"`
		AccountID   string `json:"account_id"`
		CompanyID   string `json:"company_id"`
		CompanyName string `json:"company_name"`
		Nickname    string `json:"nickname"`
		Username    string `json:"username"`
		Algorithm   string `json:"ss_algorithm"`
		Password    string `json:"ss_password"`
		PACURL      string `json:"pac_download_url"`
		VerifyURL   string `json:"verify_url"`
	} `json:"data"`
}
type _wos_res struct {
	Code int `json:"code"`
	Data struct {
		Stoken string `json:"s_token"`
		Wtoken string `json:"w_token"`
	} `json:"data"`
}

var client *http.Client

const (
	OAUTH_URL  = "https://sso.buaa.edu.cn/oauth2.0/authorize?response_type=code&state=beihang&client_id=202107201225555627401&redirect_uri=https%3A%2F%2Fwos.yjcx-tech.com"
	_UA        = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.168 Safari/537.36"
	WOS_HOST   = "wos.yjcx-tech.com"
	WOS_LOGIN  = "https://wos.yjcx-tech.com/v1/wos/company/login"
	WOS_STATUS = "https://amapi.yjcx-tech.com/v1/wos/login/status"
	COMP_ID    = "055731_211103103913"
	S_KEY      = "0tT2IKq4Hy68GYBn"
	S_IV       = "vS6T2mBkQIKoUPpw"
)

func _noRedir(req *http.Request, via []*http.Request) error {
	if req.URL.Host == WOS_HOST {
		return http.ErrUseLastResponse
	}
	return nil
}

func _wos_keepalive(token string) {
	tick := time.Tick(2 * time.Minute)
	status := &_wos_stat{}
	for {
		func() {
			req, _ := http.NewRequest("GET", WOS_STATUS, nil)
			req.Header.Set("User-Agent", _UA)
			req.Header.Set("wos-token", token)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return
			}
			if status.Code == 0 {
				data, _ := ioutil.ReadAll(resp.Body)
				err = json.Unmarshal(data, status)
				data, _ = json.Marshal(status)
				logger.Println("successfully got proxy status:", string(data))
			}
			logf("[200] wos keepalive succeed")
		}()
		<-tick
	}
}

func WosLogin(id, pw string) (token string, err error) {
	cookies, _ := cookiejar.New(nil)
	client = &http.Client{
		CheckRedirect: _noRedir,
		Jar:           cookies,
		Timeout:       8 * time.Second,
	}

	execution, err := _get_execution()
	if err != nil {
		return token, err
	}
	resp, err := client.PostForm("https://sso.buaa.edu.cn/login", url.Values{
		"username":  {id},
		"password":  {pw},
		"submit":    {"登录"},
		"type":      {"username_password"},
		"execution": {execution},
		"_eventId":  {"submit"},
	})
	if err != nil {
		return token, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		err := fmt.Errorf("[%d] Beihang login username or password is invalid", resp.StatusCode)
		return token, err
	}

	location, ok := resp.Header["Location"]
	if !ok {
		return token, errors.New("Beihang login Location not found")
	}
	resp.Body.Close()
	re := regexp.MustCompile("code=(.*)&").FindStringSubmatch(string(location[0]))
	if len(re) < 2 {
		return token, errors.New("Beihang login get_ticket error")
	}

	data, _ := json.Marshal(&_wos_login{
		Ticket:    re[1],
		CompanyID: COMP_ID,
		UAType:    1,
	})

	req, _ := http.NewRequest("POST", WOS_LOGIN, bytes.NewReader(data))
	req.Header.Set("User-Agent", _UA)
	req.Header.Set("Content-Type", "application/json")
	resp, err = client.Do(req)
	if err != nil {
		return token, err
	}
	if resp.StatusCode != http.StatusOK {
		return token, errors.New("wos login error")
	}
	data, _ = ioutil.ReadAll(resp.Body)

	result := &_wos_res{}
	err = json.Unmarshal(data, result)
	if err != nil {
		return token, err
	}

	logf("wos login succeed")
	go _wos_keepalive(result.Data.Wtoken)

	s_token, err := base64.StdEncoding.DecodeString(result.Data.Stoken)
	if err != nil {
		return token, err
	}
	token = _aes_decrypt(s_token, []byte(S_KEY), []byte(S_IV))
	if !strings.HasPrefix(token, "05573") {
		return "", errors.New("s_token decrypt error")
	}
	return token, err
}

func _get_execution() (string, error) {
	resp, err := client.Get(OAUTH_URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	result := regexp.MustCompile("<input name=\"execution\" value=\"(.*?)\"/>").FindStringSubmatch(string(body))
	if len(result) < 2 {
		return "", errors.New("Beihang login get_execution error")
	}
	return result[1], nil
}

func _aes_decrypt(enc, key, iv []byte) string {
	block, _ := aes.NewCipher(key)
	decryptor := cipher.NewCBCDecrypter(block, iv)
	data := make([]byte, len(enc))
	decryptor.CryptBlocks(data, enc)
	return string(_PKCS7_Unpadding(data))
}

func _PKCS7_Unpadding(data []byte) []byte {
	enclen := len(data)
	padlen := int(data[enclen-1])
	return data[:enclen-padlen]
}
