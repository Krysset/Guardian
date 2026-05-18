package internal

type User struct {
	UUID				string `json:"uuid"`
	Username 		string `json:"username"`
	Mail 				string `json:"mail,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type UserCredentials struct {
	UUID     string `json:"uuid"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Permission struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	PrettyName  string `json:"pretty_name"`
	Description string `json:"description"`
}

type App struct {
	UUID        string `json:"uuid"`
	Name        string `json:"name"`
	PrettyName  string `json:"pretty_name"`
	Description string `json:"description"`
	AppKey      string `json:"app_key"`
}

type FullUser struct {
	User
	Permissions []Permission `json:"permissions"`
}

type FullApp struct {
	App
	Permissions []Permission `json:"permissions"`
}

type AccountSession struct {
	SessionID   string `json:"session_id"`
	AccountID   string `json:"account_id"`
	CreationDate string `json:"creation_date"`
}