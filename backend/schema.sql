CREATE TABLE IF NOT EXISTS account_credentials
	(
		id TEXT NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		admin BOOLEAN NOT NULL DEFAULT FALSE
	);

CREATE TABLE IF NOT EXISTS account_sessions
	(
		sessionId TEXT NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
		accountId TEXT NOT NULL,
		creationDate TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (accountId) REFERENCES account_credentials(id)
	);

CREATE TABLE IF NOT EXISTS services
	(
		id TEXT NOT NULL PRIMARY KEY DEFAULT uuid_generate_v4(),
		name TEXT NOT NULL,
		description TEXT NOT NULL
	);