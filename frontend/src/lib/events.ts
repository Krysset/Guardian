// Audit events in words, for an account's recent activity (AD2) and the audit log (AD11). Unknown events
// show their type.

const words: Record<string, string> = {
	'login.success': 'Signed in',
	'login.failure': 'Failed sign-in',
	'login.password_ok': 'Password accepted, two-factor next',
	logout: 'Signed out',
	'account.signed_up': 'Signed up',
	'account.created': 'Account created',
	'account.updated': 'Account changed',
	'account.username_changed': 'Username changed',
	'account.deleted': 'Account deleted',
	'account.restored': 'Account restored',
	'account.erased': 'Account erased',
	'account.exported': 'Data downloaded',
	'account.signed_out_everywhere': 'Signed out everywhere by an administrator',
	'password.changed': 'Password changed',
	'password.set_by_admin': 'Temporary password set',
	'password.reset_requested': 'Password reset asked for',
	'password.reset': 'Password reset',
	'email.change_requested': 'Email change asked for',
	'email.change_cancelled': 'Email change cancelled',
	'email.confirmed': 'Email address confirmed',
	'email.removed': 'Email address removed',
	'mfa.totp_added': 'Two-factor turned on',
	'mfa.totp_removed': 'Two-factor turned off',
	'mfa.recovery_codes_renewed': 'New recovery codes',
	'mfa.reset': 'Two-factor reset by an administrator',
	'mfa.failure': 'Wrong two-factor code',
	'mfa.step_up': 'Confirmed with two-factor',
	'reauth.success': "Confirmed it's them",
	'reauth.failure': "Failed to confirm it's them",
	'session.revoked': 'Signed out a session',
	'session.revoked_others': 'Signed out everywhere else',
	'group.member_added': 'Added to a group',
	'group.member_removed': 'Removed from a group',
	'consent.granted': 'Allowed an app',
	'app.access_removed': "Removed an app's access",
	'authorize.denied': 'Refused by an app',
	'token.revoked': 'App token revoked',
	honeypot: 'Bot caught by the honeypot'
};

export function eventWords(type: string): string {
	return words[type] ?? type;
}
