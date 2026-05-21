package database

type User struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type UserCredentials struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	PrettyName  string `json:"pretty_name"`
	Description string `json:"description"`
}

type App struct {
	ID          string `json:"id"`
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
	SessionID    string `json:"session_id"`
	AccountID    string `json:"account_id"`
	CreationDate string `json:"creation_date"`
}
