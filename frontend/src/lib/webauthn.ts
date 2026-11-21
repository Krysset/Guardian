// Security keys and passkeys in the browser: the API sends the options for navigator.credentials as JSON
// (binary values as base64url) and takes the answer back the same way.
type Json = Record<string, unknown>;
// The API's WebAuthnOptions: { publicKey: {...} }.
type Options = unknown;

export const keysSupported = () => typeof window !== 'undefined' && 'PublicKeyCredential' in window && !!navigator.credentials;

function bytes(s: string): ArrayBuffer {
	const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
	const bin = atob(b64 + '==='.slice((b64.length + 3) % 4));
	const out = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
	return out.buffer;
}

function text(buf: ArrayBuffer): string {
	let bin = '';
	for (const b of new Uint8Array(buf)) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const withIds = (list: unknown) => ((list as { id: string }[] | undefined) ?? []).map((c) => ({ ...c, id: bytes(c.id) }));

function answer(c: PublicKeyCredential): Json {
	const r = c.response as AuthenticatorAttestationResponse & AuthenticatorAssertionResponse;
	const response: Json = { clientDataJSON: text(r.clientDataJSON) };
	if ('attestationObject' in r && r.attestationObject) {
		response.attestationObject = text(r.attestationObject);
		if (r.getTransports) response.transports = r.getTransports();
	} else {
		response.authenticatorData = text(r.authenticatorData);
		response.signature = text(r.signature);
		if (r.userHandle) response.userHandle = text(r.userHandle);
	}
	return {
		id: c.id,
		rawId: text(c.rawId),
		type: c.type,
		authenticatorAttachment: c.authenticatorAttachment ?? undefined,
		clientExtensionResults: c.getClientExtensionResults(),
		response
	};
}

/** Runs the browser's dialog to add a key, and returns its answer for the API. */
export async function createKey(options: Options): Promise<Json> {
	const pk = (options as { publicKey: Json & { user: Json } }).publicKey;
	const c = (await navigator.credentials.create({
		publicKey: {
			...pk,
			challenge: bytes(pk.challenge as string),
			user: { ...pk.user, id: bytes(pk.user.id as string) },
			excludeCredentials: withIds(pk.excludeCredentials)
		} as unknown as PublicKeyCredentialCreationOptions
	})) as PublicKeyCredential | null;
	if (!c) throw new DOMException('No key', 'NotAllowedError');
	return answer(c);
}

/** Runs the browser's dialog to use one of the account's keys, and returns its answer for the API. */
export async function useKey(options: Options): Promise<Json> {
	const pk = (options as { publicKey: Json }).publicKey;
	const c = (await navigator.credentials.get({
		publicKey: { ...pk, challenge: bytes(pk.challenge as string), allowCredentials: withIds(pk.allowCredentials) } as unknown as PublicKeyCredentialRequestOptions
	})) as PublicKeyCredential | null;
	if (!c) throw new DOMException('No key', 'NotAllowedError');
	return answer(c);
}

/** keyError says what went wrong with the browser's dialog, or null when it was not the dialog. */
export function keyError(e: unknown): string | null {
	if (!(e instanceof DOMException)) return null;
	if (e.name === 'NotAllowedError') return 'The request was cancelled or timed out. Try again.';
	if (e.name === 'InvalidStateError') return 'That key is already registered.';
	return 'This browser could not use the key. Try again.';
}
