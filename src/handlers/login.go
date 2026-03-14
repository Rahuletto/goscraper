package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/valyala/fasthttp"
)

type LoginFetcher struct{}

type LoginResponse struct {
	Authenticated bool                   `json:"authenticated"`
	Session       map[string]interface{} `json:"session"`
	Lookup        any                    `json:"lookup"`
	Cookies       string                 `json:"cookies"`
	Status        int                    `json:"status"`
	Message       any                    `json:"message"`
	Errors        []string               `json:"errors"`
	Captcha       *CaptchaData           `json:"captcha,omitempty"`
}

type CaptchaData struct {
	Image   string `json:"image"`   // base64 encoded image
	Cdigest string `json:"cdigest"` // captcha digest
}

func (lf *LoginFetcher) Logout(token string) (map[string]interface{}, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://academia.srmist.edu.in/accounts/p/10002227248/logout?servicename=ZohoCreator&serviceurl=https://academia.srmist.edu.in")
	req.Header.SetMethod("GET")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Cookie", token)

	if err := fasthttp.Do(req, resp); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"status":  resp.StatusCode(),
		"success": resp.StatusCode() == 200 || resp.StatusCode() == 302,
	}, nil
}

func (lf *LoginFetcher) Login(username, password string, cdigest, captcha *string) (*LoginResponse, error) {
	fullUsername := username
	if !strings.Contains(fullUsername, "@") {
		fullUsername += "@srmist.edu.in"
	}
	return lf.loginWithRetry(fullUsername, password, cdigest, captcha, 0, make(map[string]string))
}

func (lf *LoginFetcher) loginWithRetry(username, password string, cdigest, captcha *string, retryCount int, jar map[string]string) (*LoginResponse, error) {
	if retryCount > 2 {
		return &LoginResponse{
			Authenticated: false,
			Status:        401,
			Message:       "Too many retries after concurrent session termination",
		}, nil
	}

	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://academia.srmist.edu.in/accounts/signin.ac")
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Header.Set("Origin", "https://academia.srmist.edu.in")
	req.Header.Set("Referer", "https://academia.srmist.edu.in/")

	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	args.Add("username", username)
	args.Add("password", password)
	args.Add("client_portal", "true")
	args.Add("portal", "10002227248")
	args.Add("servicename", "ZohoCreator")
	args.Add("serviceurl", "https://academia.srmist.edu.in/")
	args.Add("is_ajax", "true")
	args.Add("grant_type", "password")
	args.Add("service_language", "en")

	if cdigest != nil && *cdigest != "" {
		args.Add("cdigest", *cdigest)
	}
	if captcha != nil && *captcha != "" {
		args.Add("captcha", *captcha)
	}
	req.SetBody(args.QueryString())

	if err := fasthttp.Do(req, resp); err != nil {
		return nil, err
	}

	lf.extractCookies(resp, jar)
	body := resp.Body()

	if strings.Contains(strings.ToLower(string(body)), "concurrent") || strings.Contains(strings.ToLower(string(body)), "terminate") {
		if lf.forceLogout(body, jar) {
			return lf.loginWithRetry(username, password, cdigest, captcha, retryCount+1, jar)
		}
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return &LoginResponse{
			Authenticated: false,
			Status:        resp.StatusCode(),
			Message:       "Unexpected response from server",
		}, nil
	}

	if errMap, ok := data["error"].(map[string]interface{}); ok {
		errMsg, _ := errMap["msg"].(string)
		return &LoginResponse{Authenticated: false, Status: 401, Message: errMsg}, nil
	}

	if status, ok := data["status"].(string); ok && status == "fail" {
		if code, ok := data["code"].(string); ok && (code == "HIP_REQUIRED" || code == "HIP_FAILED") {
			captchaData := &CaptchaData{}
			if cdig, ok := data["cdigest"].(string); ok {
				captchaData.Cdigest = cdig
				captchaData.Image = fmt.Sprintf("https://academia.srmist.edu.in/accounts/p/40-10002227248/webclient/v1/captcha/%s?darkmode=false", cdig)
			}
			return &LoginResponse{Authenticated: false, Status: 401, Message: data["message"], Captcha: captchaData}, nil
		}
	}

	innerData, ok := data["data"].(map[string]interface{})
	if !ok {
		msg, _ := data["message"].(string)
		return &LoginResponse{Authenticated: false, Status: 401, Message: msg, Errors: []string{"Invalid credentials"}}, nil
	}

	accessToken, _ := innerData["access_token"].(string)
	redirectURL, _ := innerData["oauthorize_uri"].(string)

	if accessToken == "" || redirectURL == "" {
		return &LoginResponse{Authenticated: false, Status: 401, Message: "Missing tokens in response"}, nil
	}

	finalAuthURL := fmt.Sprintf("%s&access_token=%s", redirectURL, accessToken)
	req.Reset()
	req.SetRequestURI(finalAuthURL)
	req.Header.SetMethod("GET")
	req.Header.Set("Cookie", lf.getCookieStr(jar))
	resp.Reset()

	if err := fasthttp.DoRedirects(req, resp, 10); err != nil {
		return nil, err
	}

	lf.extractCookies(resp, jar)
	cookieStr := lf.getCookieStr(jar)

	if !strings.Contains(cookieStr, "JSESSIONID") {
		return &LoginResponse{Authenticated: false, Status: 401, Message: "Session failed: JSESSIONID not established"}, nil
	}

	return &LoginResponse{
		Authenticated: true,
		Cookies:       cookieStr,
		Status:        200,
		Message:       "Success",
		Session:       map[string]interface{}{"success": true},
	}, nil
}

func (lf *LoginFetcher) forceLogout(body []byte, jar map[string]string) bool {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
	if err != nil {
		return false
	}
	var terminateForm *goquery.Selection
	doc.Find("form").Each(func(i int, s *goquery.Selection) {
		if strings.Contains(strings.ToLower(s.Text()), "terminate") {
			terminateForm = s
		}
	})
	if terminateForm == nil {
		return false
	}
	action, _ := terminateForm.Attr("action")
	if !strings.HasPrefix(action, "http") {
		action = "https://academia.srmist.edu.in" + action
	}
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI(action)
	req.Header.SetMethod("POST")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", lf.getCookieStr(jar))
	args := fasthttp.AcquireArgs()
	defer fasthttp.ReleaseArgs(args)
	terminateForm.Find("input").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		if name != "" {
			val, _ := s.Attr("value")
			args.Add(name, val)
		}
	})
	req.SetBody(args.QueryString())
	if err := fasthttp.Do(req, resp); err != nil {
		return false
	}
	lf.extractCookies(resp, jar)
	return resp.StatusCode() == 200
}

func (lf *LoginFetcher) extractCookies(resp *fasthttp.Response, jar map[string]string) {
	resp.Header.VisitAllCookie(func(key, value []byte) {
		c := fasthttp.AcquireCookie()
		defer fasthttp.ReleaseCookie(c)
		c.ParseBytes(value)
		if val := string(c.Value()); val != "" && val != "delete" && val != "null" {
			jar[string(key)] = val
		}
	})
}

func (lf *LoginFetcher) getCookieStr(jar map[string]string) string {
	var parts []string
	for k, v := range jar {
		parts = append(parts, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(parts, "; ")
}

func (lf *LoginFetcher) Cleanup(cookie string) (int, error) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://academia.srmist.edu.in/accounts/p/10002227248/webclient/v1/account/self/user/self/activesessions")
	req.Header.SetMethod("DELETE")
	req.Header.Set("Cookie", cookie)

	if err := fasthttp.Do(req, resp); err != nil {
		return 0, err
	}
	return resp.StatusCode(), nil
}
