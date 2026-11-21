// Audit events in words, for recent activity (AD2, AD8) and the audit log (AD11). Unknown events show
// their type.
import type { Schema } from '#lib/api/client.ts';

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
	'account.admin_recovered': 'Made an administrator from the database (runbook)',
	'password.changed': 'Password changed',
	'password.set_by_admin': 'Temporary password set',
	'password.reset_requested': 'Password reset asked for',
	'password.reset': 'Password reset',
	'email.change_requested': 'Email change asked for',
	'email.change_cancelled': 'Email change cancelled',
	'email.confirmed': 'Email address confirmed',
	'email.removed': 'Email address removed',
	'mfa.totp_added': 'Authenticator app added',
	'mfa.totp_removed': 'Authenticator app removed',
	'mfa.key_added': 'Security key added',
	'mfa.key_renamed': 'Security key renamed',
	'mfa.key_removed': 'Security key removed',
	'mfa.key_clone_warning': 'Security key refused: it may have been copied',
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
	honeypot: 'Bot caught by the honeypot',
	'app.created': 'App registered',
	'app.updated': 'Settings changed',
	'app.access_changed': 'Access changed',
	'app.secret_rotated': 'Secret rotated',
	'app.removed': 'App deleted',
	'group.created': 'Group created',
	'group.updated': 'Group changed',
	'group.bound': 'Group bound to an app',
	'group.deleted': 'Group deleted',
	'signing_key.created': 'Signing key created',
	'signing_key.activated': 'Signing key put in use',
	'signing_key.retired': 'Signing key retired',
	'backup.created': 'Backup made',
	'backup.restored': 'Backup restored',
	'backup.restore_failed': 'Backup restore failed'
};

// The event types for the audit log's filter, in groups.
export const eventGroups: { label: string; types: string[] }[] = [
	['Signing in', ['login.', 'logout', 'mfa.', 'reauth.', 'session.', 'authorize.', 'honeypot']],
	['Accounts', ['account.', 'password.', 'email.']],
	['Groups', ['group.']],
	['Apps', ['app.', 'consent.', 'token.']],
	['Guardian', ['signing_key.', 'backup.']]
].map(([label, prefixes]) => ({
	label: label as string,
	types: Object.keys(words).filter((t) => (prefixes as string[]).some((p) => t === p || (p.endsWith('.') && t.startsWith(p))))
}));


type Metadata = Record<string, unknown>;

// eventWords names an event. With its details, a change that turned something off or on says so.
export function eventWords(type: string, metadata: Metadata = {}): string {
	if (type === 'app.updated' && typeof metadata.enabled === 'boolean') return metadata.enabled ? 'App enabled' : 'App disabled';
	if (type === 'account.updated' && metadata.status === 'disabled') return 'Account disabled';
	if (type === 'account.updated' && metadata.status === 'active') return 'Account enabled';
	return words[type] ?? type;
}

const durations: Record<number, string> = { 0: 'at once', 3600: 'after 1 hour', 86400: 'after 1 day', 604800: 'after 7 days' };

// summary says in a few words what an entry was about: the account, group or app, and the detail that
// matters. Names come from the API while they exist; the key or app name kept in the entry stands in after.
export function summary(e: Schema<'AuditEntry'>): string {
	const m = (e.metadata ?? {}) as Metadata;
	const text = (v: unknown) => (typeof v === 'string' && v ? v : '');
	const account = e.target_username || text(m.username);
	const group = e.group_name || text(m.key);
	const app = e.app_name || text(m.name);
	const parts: string[] = [];
	switch (e.event_type) {
		case 'group.member_added':
			parts.push([account, group && `to ${group}`].filter(Boolean).join(' '));
			if (text(m.expires_at)) parts.push(`until ${new Date(text(m.expires_at)).toLocaleDateString()}`);
			break;
		case 'group.member_removed':
			parts.push([account, group && `from ${group}`].filter(Boolean).join(' '));
			break;
		case 'login.failure':
			parts.push(text(m.username) && `as ${text(m.username)}`, m.method === 'passkey' ? 'with a passkey' : '');
			break;
		case 'login.success':
		case 'mfa.step_up':
			parts.push(m.method === 'passkey' ? 'with a passkey' : m.method === 'security_key' ? `with ${text(m.key) ? `“${text(m.key)}”` : 'a security key'}` : m.method === 'recovery_code' ? 'with a recovery code' : '');
			break;
		case 'mfa.key_added':
		case 'mfa.key_clone_warning':
		case 'mfa.key_renamed':
		case 'mfa.key_removed':
			parts.push(text(m.key) && `“${text(m.key)}”`);
			break;
		case 'mfa.reset':
			parts.push(account, text(m.reason) && `“${text(m.reason)}”`);
			break;
		case 'app.secret_rotated':
			parts.push(app, typeof m.grace_seconds === 'number' ? `old secret stops ${durations[m.grace_seconds] ?? `after ${m.grace_seconds} s`}` : '');
			break;
		case 'app.access_changed':
			parts.push(app, m.access_rule === 'anyone' ? 'anyone with an account' : m.access_rule === 'groups' ? 'linked groups only' : '');
			break;
		case 'consent.granted':
			parts.push(app, Array.isArray(m.scopes) ? m.scopes.join(' ') : '');
			break;
		case 'account.updated':
			parts.push(account, m.email_changed ? 'email changed' : '', text(m.username) && `username ${text(m.username)}`);
			break;
		case 'account.deleted':
		case 'account.erased':
			parts.push(account, m.by === 'self' ? 'by themselves' : m.by === 'schedule' ? 'after the grace period' : '');
			break;
		case 'signing_key.created':
		case 'signing_key.activated':
		case 'signing_key.retired':
			parts.push(text(m.kid));
			break;
		case 'backup.created':
		case 'backup.restored':
		case 'backup.restore_failed':
			parts.push(text(m.reason));
			break;
		default:
			parts.push(e.event_type.startsWith('group.') ? group : '', account !== e.actor_username ? account : '', e.event_type.startsWith('app.') || e.event_type.startsWith('authorize.') || e.event_type.startsWith('token.') ? app : '');
	}
	return parts.filter(Boolean).join(' · ');
}

// who names whoever did it: an account, an app acting by itself, Guardian on its own schedule or from the
// command line, or someone unknown (a failed sign-in with no such account, a bot).
export function who(e: Schema<'AuditEntry'>): string {
	if (e.actor_username) return e.actor_username;
	if (e.actor_account_id) return 'An erased account';
	if (e.actor_app_id) return e.app_name || 'A deleted app';
	const m = (e.metadata ?? {}) as Metadata;
	if (m.by === 'schedule' || /^(signing_key|backup)\./.test(e.event_type)) return 'Guardian';
	return 'Someone';
}
