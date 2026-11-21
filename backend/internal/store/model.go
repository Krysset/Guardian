package store

import "time"

type Account struct {
	ID                 string     `json:"id"`
	Username           string     `json:"username"`
	DisplayName        string     `json:"display_name,omitempty"`
	GivenName          string     `json:"given_name,omitempty"`
	FamilyName         string     `json:"family_name,omitempty"`
	PictureURL         string     `json:"picture_url,omitempty"`
	Locale             string     `json:"locale,omitempty"`
	Zoneinfo           string     `json:"zoneinfo,omitempty"`
	Email              string     `json:"email,omitempty"`
	EmailVerified      bool       `json:"email_verified"`
	Status             string     `json:"status"`
	MustChangePassword bool       `json:"must_change_password"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
	LastLoginAt        *time.Time `json:"last_login_at,omitempty"`
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
	AccessTokenTTL          int      `json:"access_token_ttl_seconds"` // lifetime of access and ID tokens; also how stale the app's view of a user can get
	RefreshMode             string   `json:"refresh_mode"`             // "stable" (apps with a secret) or "none"
	Enabled                 bool     `json:"enabled"`
	AccessRule              string   `json:"access_rule"`              // "groups" (only members of linked groups may sign in) or "anyone"
	RequireMFA              bool     `json:"require_mfa"`              // signing in to the app needs two-factor
	SigningAlg              string   `json:"signing_alg"`              // RS256 or ES256: the algorithm of the app's tokens
	OwnerGroupID            string   `json:"owner_group_id,omitempty"` // its members are the app's admins
	GroupIDs                []string `json:"group_ids"`                // groups linked to the app
	Scopes                  []string `json:"scopes,omitempty"`         // scopes the app may request (filled by GetAppByClientID)
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
	AMR        []string  // how the user proved who they are, for the OIDC amr claim
	ExpiresAt  time.Time // absolute end of the session
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
	AppID     string
	AccountID string
	SessionID string
	Scopes    []string
}

type SigningKey struct {
	KID                 string     `json:"kid"`
	Alg                 string     `json:"alg"`
	PublicJWK           []byte     `json:"-"`
	PrivateKeyEncrypted string     `json:"-"`
	Status              string     `json:"status"` // pending, active, retiring or retired
	CreatedAt           time.Time  `json:"created_at"`
	ActivatedAt         *time.Time `json:"activated_at,omitempty"`
	RetireAt            *time.Time `json:"retire_at,omitempty"`
	RetiredAt           *time.Time `json:"retired_at,omitempty"`
}

// LogoutTarget is an app that must be told (back-channel) that a session ended.
type LogoutTarget struct {
	ClientID   string
	URI        string
	SigningAlg string // the app's token algorithm, for its logout token
}

// LogoutNotice is one back-channel logout to send: this app must drop what it holds for this session.
type LogoutNotice struct {
	LogoutTarget
	AccountID string
	SessionID string
}
