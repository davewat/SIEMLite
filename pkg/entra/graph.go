package entra

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Where Microsoft's public cloud is. The Service can point elsewhere for tests.
const (
	DefaultAuthority = "https://login.microsoftonline.com"
	DefaultGraph     = "https://graph.microsoft.com/v1.0"
)

const maxBody = 4 << 20

func limit(resp *http.Response) io.Reader { return io.LimitReader(resp.Body, maxBody) }

// graphError is an answer from Microsoft that wasn't a success.
type graphError struct {
	Status  int
	Code    string
	Message string
}

func (e *graphError) Error() string {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "Microsoft Graph refused the request. Give the app the GroupMember.Read.All application permission and grant admin consent for it."
	case http.StatusNotFound:
		return "Microsoft Graph couldn't find that group. Check the group's Object ID."
	}
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.Status)
	}
	return fmt.Sprintf("Microsoft Graph answered %d: %s", e.Status, trim(msg))
}

func trim(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// appToken returns an access token for Microsoft Graph, using the app's own
// credentials (not a person's).
func (s *Service) appToken(ctx context.Context, cfg Config, secret string) (string, error) {
	key := cfg.TenantID + "|" + cfg.ClientID + "|" + secret
	s.tokMu.Lock()
	if t, ok := s.tokens[key]; ok && time.Now().Before(t.exp) {
		s.tokMu.Unlock()
		return t.token, nil
	}
	s.tokMu.Unlock()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {cfg.ClientID}, "client_secret": {secret},
		"scope": {"https://graph.microsoft.com/.default"}}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := s.tokenRequest(ctx, cfg, form, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("Entra didn't return an access token")
	}
	s.tokMu.Lock()
	if s.tokens == nil || len(s.tokens) > 8 {
		s.tokens = map[string]cachedToken{}
	}
	s.tokens[key] = cachedToken{token: out.AccessToken, exp: time.Now().Add(time.Duration(out.ExpiresIn)*time.Second - time.Minute)}
	s.tokMu.Unlock()
	return out.AccessToken, nil
}

// tokenRequest posts to the tenant's token endpoint and decodes the answer.
func (s *Service) tokenRequest(ctx context.Context, cfg Config, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.authority()+"/"+cfg.TenantID+"/oauth2/v2.0/token", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("Couldn't reach Entra: %s", trim(err.Error()))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(limit(resp))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		desc := e.Description
		if i := strings.Index(desc, "Trace ID"); i > 0 {
			desc = desc[:i]
		}
		switch e.Error {
		case "invalid_client", "unauthorized_client":
			return fmt.Errorf("Entra rejected the application ID or client secret: %s", trim(desc))
		case "invalid_grant":
			return fmt.Errorf("Entra rejected the sign-in code or redirect URL: %s", trim(desc))
		}
		return fmt.Errorf("Entra answered %d: %s", resp.StatusCode, trim(desc))
	}
	return json.Unmarshal(body, out)
}

// graph calls Microsoft Graph. path is relative to the Graph base, or a full
// URL from an @odata.nextLink (checked to be on Graph).
func (s *Service) graph(ctx context.Context, token, method, path string, in, out any) error {
	full := s.graphURL() + path
	if strings.HasPrefix(path, "http") {
		if !strings.HasPrefix(path, s.graphURL()+"/") {
			return errors.New("Microsoft Graph sent a link to another site, which was ignored")
		}
		full = path
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, full, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("Couldn't reach Microsoft Graph: %s", trim(err.Error()))
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(limit(resp))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		return &graphError{Status: resp.StatusCode, Code: e.Error.Code, Message: e.Error.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// isMember reports whether a person is in a group, directly or through a
// nested group.
func (s *Service) isMember(ctx context.Context, token, groupID, objectID string) (bool, error) {
	var out struct {
		Value []string `json:"value"`
	}
	if err := s.graph(ctx, token, http.MethodPost, "/groups/"+groupID+"/checkMemberObjects", map[string][]string{"ids": {objectID}}, &out); err != nil {
		return false, err
	}
	for _, id := range out.Value {
		if strings.EqualFold(id, objectID) {
			return true, nil
		}
	}
	return false, nil
}

// groupName returns a group's display name.
func (s *Service) groupName(ctx context.Context, token, groupID string) (string, error) {
	var out struct {
		Name string `json:"displayName"`
	}
	if err := s.graph(ctx, token, http.MethodGet, "/groups/"+groupID+"?$select=id,displayName", nil, &out); err != nil {
		return "", err
	}
	return out.Name, nil
}

const maxMemberPages = 200

// members returns the people in a group, nested groups included, mapped to
// whether their Microsoft account is enabled. An error means the list is
// incomplete and must not be acted on.
func (s *Service) members(ctx context.Context, token, groupID string) (map[string]bool, error) {
	out := map[string]bool{}
	next := "/groups/" + groupID + "/transitiveMembers/microsoft.graph.user?$select=id,accountEnabled&$top=999"
	for page := 0; next != ""; page++ {
		if page >= maxMemberPages {
			return nil, errors.New("the group has too many members to read")
		}
		var res struct {
			Value []struct {
				ID      string `json:"id"`
				Enabled *bool  `json:"accountEnabled"`
			} `json:"value"`
			Next string `json:"@odata.nextLink"`
		}
		if err := s.graph(ctx, token, http.MethodGet, next, nil, &res); err != nil {
			return nil, err
		}
		for _, m := range res.Value {
			out[strings.ToLower(m.ID)] = m.Enabled == nil || *m.Enabled
		}
		next = res.Next
	}
	return out, nil
}
