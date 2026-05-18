-- Table for storing account credentials, optionally set mail for account recovery. Username is unique and password is stored as a hash.
CREATE TABLE IF NOT EXISTS account
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		mail TEXT,
		display_name TEXT,
		creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

-- Table for storing apps, app key is used to obfuscate the app id and is used for authentication when an app tries to access the API. app_key should be able to be regenerated.
CREATE TABLE IF NOT EXISTS app
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		name TEXT NOT NULL,
		pretty_name TEXT NOT NULL,
		description TEXT NOT NULL,
		app_key UUID NOT NULL UNIQUE DEFAULT gen_random_uuid()
	);

-- Table for storing permissions, permissions are used to control access to the API. Each permission has a name and a description.
CREATE TABLE IF NOT EXISTS permission
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		name TEXT NOT NULL,
		pretty_name TEXT NOT NULL,
		description TEXT NOT NULL
	);

-- Table for storing account sessions, each session is associated with an account and has a creation date. This is used to track active sessions and can be used for session management.
CREATE TABLE IF NOT EXISTS account_session
	(
		session_id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL,
		creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT fk_account_id FOREIGN KEY (account_id) REFERENCES account(id)
	);

-- Table for storing app permissions. This is used to control which apps need which permissions.
CREATE TABLE IF NOT EXISTS app_permission
	(
		app_id UUID NOT NULL,
		permission_id UUID NOT NULL,
		is_required BOOLEAN NOT NULL DEFAULT TRUE,
		PRIMARY KEY (app_id, permission_id),
		CONSTRAINT fk_app_id FOREIGN KEY (app_id) REFERENCES app(id),
		CONSTRAINT fk_permission_id FOREIGN KEY (permission_id) REFERENCES permission(id)
	);

-- Table for storing admin permissions, this is used to control which accounts have access to which permissions.
CREATE TABLE IF NOT EXISTS admin_permission
	(
		account_id UUID NOT NULL,
		permission_id UUID NOT NULL,
		PRIMARY KEY (account_id, permission_id),
		CONSTRAINT fk_account_id FOREIGN KEY (account_id) REFERENCES account(id),
		CONSTRAINT fk_permission_id FOREIGN KEY (permission_id) REFERENCES permission(id)
	);

CREATE TABLE IF NOT EXISTS account_reset_codes
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL,
		reset_code string NOT NULL,
		used BOOLEAN NOT NULL DEFAULT FALSE,
		creation_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT fk_account_id FOREIGN KEY (account_id) REFERENCES account(id)
	);

-- If tables are empty initialize a admin user with admin permissions
IF(NOT EXISTS (SELECT 1 FROM permission)) THEN
	INSERT INTO permission (name, pretty_name, description) VALUES ('admin', 'Admin', 'Grants full access to all permissions');
END IF;
IF(NOT EXISTS (SELECT 1 FROM account)) THEN
	INSERT INTO account (username, password, display_name) VALUES ('admin', 'admin_password', 'Admin');
END IF;
IF(NOT EXISTS (SELECT 1 FROM admin_permission)) THEN
	INSERT INTO admin_permission (account_id, permission_id) SELECT a.id, p.id FROM account a, permission p WHERE a.username = 'admin' AND p.name = 'admin';
END IF;