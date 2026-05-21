-- Table for storing account credentials, optionally set email for account recovery. Username is unique and password is stored as a hash.
CREATE TABLE IF NOT EXISTS account
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL,
		email TEXT,
		display_name TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
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

-- Table for storing app permissions. This is used to control which apps need which permissions.
CREATE TABLE IF NOT EXISTS app_permission
	(
		app_id UUID NOT NULL,
		permission_id UUID NOT NULL,
		PRIMARY KEY (app_id, permission_id),
		CONSTRAINT fk_app_id FOREIGN KEY (app_id) REFERENCES app(id),
		CONSTRAINT fk_permission_id FOREIGN KEY (permission_id) REFERENCES permission(id)
	);

-- Table for storing admin permissions, this is used to control which accounts have access to which permissions.
CREATE TABLE IF NOT EXISTS account_permission
	(
		account_id UUID NOT NULL,
		permission_id UUID NOT NULL,
		app_id UUID NOT NULL,
		PRIMARY KEY (account_id, permission_id, app_id),
		CONSTRAINT fk_account_id FOREIGN KEY (account_id) REFERENCES account(id),
		CONSTRAINT fk_permission_id FOREIGN KEY (permission_id) REFERENCES permission(id)
	);

-- Table for storing password reset codes, each code is associated with an account and has a creation date.
	(
		id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL,
		reset_code string NOT NULL,
		used BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		CONSTRAINT fk_account_id FOREIGN KEY (account_id) REFERENCES account(id)
	);


-- TODO: Needs more work, not finished
CREATE TABLE IF NOT EXISTS account_access_token
	(
		token_id UUID NOT NULL PRIMARY KEY DEFAULT gen_random_uuid(),
		account_id UUID NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		hashed_token TEXT NOT NULL,
		CONSTRAINT fk_account_id FOREIGN KEY (account_id) REFERENCES account(id)
	);

-- If guardian does not exist initialize it with a default app and permissions
IF(NOT EXISTS (SELECT 1 FROM app)) THEN
	INSERT INTO app (name, pretty_name, description) VALUES ('guardian', 'Guardian', 'Service for managing accounts and app permissions');
END IF;
-- TODO: Change this to only give guardian the permissions it needs, currently it has all permissions for testing purposes
IF(NOT EXISTS (SELECT 1 FROM app_permission)) THEN
	INSERT INTO app_permission (app_id, permission_id) SELECT a.id, p.id FROM app a, permission p WHERE a.name = 'guardian' AND p.name = 'admin'; 
END IF;

-- If tables are empty initialize a admin user with admin permissions
IF(NOT EXISTS (SELECT 1 FROM permission)) THEN
	INSERT INTO permission (name, pretty_name, description) VALUES ('admin', 'Admin', 'Grants full access to all permissions');
END IF;
IF(NOT EXISTS (SELECT 1 FROM account)) THEN
	INSERT INTO account (username, password, display_name) VALUES ('admin', 'admin_password', 'Admin');
END IF;
IF(NOT EXISTS (SELECT 1 FROM account_permission)) THEN
	INSERT INTO account_permission (account_id, permission_id) SELECT a.id, p.id FROM account a, permission p WHERE a.username = 'admin' AND p.name = 'admin';
END IF;

