package database

import "time"

type Account struct {
	ID                 string    `json:"id"`
	Username           string    `json:"username"`
	DisplayName        string    `json:"display_name,omitempty"`
	GivenName          string    `json:"given_name,omitempty"`
	FamilyName         string    `json:"family_name,omitempty"`
	PictureURL         string    `json:"picture_url,omitempty"`
	Locale             string    `json:"locale,omitempty"`
	Zoneinfo           string    `json:"zoneinfo,omitempty"`
	Email              string    `json:"email,omitempty"`
	EmailVerified      bool      `json:"email_verified"`
	PhoneNumber        string    `json:"phone_number,omitempty"`
	PhoneVerified      bool      `json:"phone_number_verified"`
	Status             string    `json:"status"`
	MustChangePassword bool      `json:"must_change_password"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// App is an OIDC client. Secrets are never part of this struct (see app_secret).
type App struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	PrettyName              string   `json:"pretty_name"`
	Description             string   `json:"description"`
	LogoURL                 string   `json:"logo_url,omitempty"`
	HomepageURL             string   `json:"homepage_url,omitempty"`
	ClientID                string   `json:"client_id"`
	ClientType              string   `json:"client_type"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	RedirectURIs            []string `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string `json:"post_logout_redirect_uris"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri,omitempty"`
	RequirePKCE             bool     `json:"require_pkce"`
	IsFirstParty            bool     `json:"is_first_party"`
	AccessTokenTTL          int      `json:"access_token_ttl_seconds"`
	RefreshTokenTTL         int      `json:"refresh_token_ttl_seconds"`
	Enabled                 bool     `json:"enabled"`
	Scopes                  []string `json:"scopes,omitempty"` // scopes the app may request (filled by GetAppByClientID)
}

type Scope struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Claims      []string `json:"claims"`
}

type Session struct {
	ID         string
	AccountID  string
	AuthTime   time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
}

type AuthCode struct {
	AppID         string
	AccountID     string
	SessionID     string
	RedirectURI   string
	Scopes        []string
	Nonce         string
	CodeChallenge string
	AuthTime      time.Time
}

type RefreshToken struct {
	ID        string
	FamilyID  string
	AppID     string
	AccountID string
	SessionID string
	Scopes    []string
}

type SigningKey struct {
	KID                 string
	Alg                 string
	PublicJWK           []byte
	PrivateKeyEncrypted string
	Status              string
}

// LogoutTarget is an app that must be told (back-channel) that a session ended.
type LogoutTarget struct {
	ClientID string
	URI      string
}
