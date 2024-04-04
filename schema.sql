CREATE TABLE IF NOT EXISTS account_credentials
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid() ,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		admin BOOLEAN NOT NULL DEFAULT FALSE
	);

CREATE TABLE IF NOT EXISTS account_sessions
	(
		sessionId UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid() ,
		accountId UUID NOT NULL,
		creationDate TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (accountId) REFERENCES account_credentials(id)
	);

CREATE TABLE IF NOT EXISTS services
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid() ,
		name TEXT NOT NULL,
		description TEXT NOT NULL,
		serviceKey UUID NOT NULL UNIQUE DEFAULT gen_random_uuid()
	);