// The management UI's client for Guardian's API (/api/v1, described by docs/openapi.yaml). The types come
// from schema.d.ts, generated with `npm run api`; regenerate it whenever openapi.yaml changes.
//
// Every call shares three behaviours:
// - 401 (not signed in, or the session ended): the browser goes to the sign-in page and comes back here.
// - 403 reauth_required (a protected change): the "Confirm it's you" dialog (AC8) opens; once the user
//   confirms, the call is sent again. Cancelling rejects with ApiError code "cancelled".
// - Any other failure rejects with an ApiError carrying the API's error code and message.

import { error } from '@sveltejs/kit';
import type { paths } from './schema.d.ts';
import { confirmIdentity } from '#lib/reauth.svelte.ts';

type Method = 'get' | 'post' | 'put' | 'patch' | 'delete';
type PathsWith<M extends Method> = {
	[P in keyof paths]: paths[P] extends Record<M, infer O> ? (O extends undefined | never ? never : P) : never;
}[keyof paths];
type Op<P extends keyof paths, M extends Method> = NonNullable<paths[P][M & keyof paths[P]]>;

type JSONContent<T> = T extends { content: { 'application/json': infer B } } ? B : never;
type BodyOf<O> = O extends { requestBody: infer R } ? JSONContent<R> : O extends { requestBody?: infer R } ? JSONContent<NonNullable<R>> : never;
type ResultOf<O> = O extends { responses: infer R }
	? R extends { 200: infer S }
		? JSONContent<S>
		: R extends { 201: infer S }
			? JSONContent<S>
			: R extends { 202: infer S }
				? JSONContent<S>
				: void
	: never;
type PathParams<O> = O extends { parameters: { path: infer P } } ? (P extends undefined | never ? never : P) : never;
type QueryParams<O> = O extends { parameters: { query?: infer Q } } ? Q : never;

export type Options<O> = {
	path?: PathParams<O>;
	query?: QueryParams<O>;
	body?: BodyOf<O>;
	/** What the change is, for the "Confirm it's you" dialog: "change your email address". */
	reason?: string;
};

/** A failed API call. code is the API's error code (reauth_required, last_admin, ...) or "cancelled". */
export class ApiError extends Error {
	constructor(
		readonly status: number,
		readonly code: string,
		message: string
	) {
		super(message);
	}
}

const base = '/api/v1';

function url(template: string, path?: Record<string, unknown>, query?: Record<string, unknown>): string {
	let p = template.replace(/\{(\w+)\}/g, (_, name: string) => {
		const v = path?.[name];
		if (v === undefined) throw new Error(`missing path parameter ${name} for ${template}`);
		return encodeURIComponent(String(v));
	});
	if (query) {
		const q = new URLSearchParams();
		for (const [k, v] of Object.entries(query)) {
			if (v !== undefined && v !== null && v !== '') q.set(k, String(v));
		}
		const s = q.toString();
		if (s) p += '?' + s;
	}
	return base + p;
}

/** Sends the browser to the sign-in page, which brings it back to the current page. The promise never
 *  settles: the page is being left, so nothing should render an error meanwhile. */
export function signIn(): Promise<never> {
	const back = location.pathname + location.search;
	location.assign('/login?return_to=' + encodeURIComponent(back));
	return new Promise(() => {});
}

async function send(method: Method, template: string, opts: Options<unknown>, fetcher: typeof fetch): Promise<unknown> {
	const init: RequestInit = {
		method: method.toUpperCase(),
		headers: { Accept: 'application/json' },
		credentials: 'same-origin'
	};
	if (opts.body !== undefined) {
		init.headers = { ...init.headers, 'Content-Type': 'application/json' };
		init.body = JSON.stringify(opts.body);
	}
	const target = url(template, opts.path as unknown as Record<string, unknown>, opts.query as unknown as Record<string, unknown>);

	for (let attempt = 0; ; attempt++) {
		let res: Response;
		try {
			res = await fetcher(target, init);
		} catch {
			throw new ApiError(0, 'network', "Guardian can't be reached. Check your connection and try again.");
		}
		if (res.ok) {
			if (res.status === 204) return undefined;
			const type = res.headers.get('Content-Type') ?? '';
			return type.includes('application/json') ? res.json() : res.blob();
		}
		let code = 'server_error';
		let message = 'Something went wrong. Try again.';
		try {
			const e = (await res.json()) as { error?: string; message?: string };
			code = e.error ?? code;
			message = e.message ?? message;
		} catch {
			// not a JSON error (a proxy's page, say): keep the generic message
		}
		if (res.status === 401) return signIn();
		if (res.status === 403 && code === 'reauth_required' && attempt === 0) {
			if (await confirmIdentity(opts.reason ?? 'make this change')) continue;
			throw new ApiError(403, 'cancelled', 'Cancelled');
		}
		throw new ApiError(res.status, code, message);
	}
}

function caller<M extends Method>(method: M) {
	return <P extends PathsWith<M>>(path: P, opts: Options<Op<P, M>> = {}, fetcher: typeof fetch = fetch) =>
		send(method, path as string, opts as Options<unknown>, fetcher) as Promise<ResultOf<Op<P, M>>>;
}

/** Typed calls: api.get('/me'), api.patch('/me', { body: { display_name: 'Link' } }). */
export const api = {
	get: caller('get'),
	post: caller('post'),
	put: caller('put'),
	patch: caller('patch'),
	delete: caller('delete')
};

/** The JSON shape of a schema in openapi.yaml: Schema<'Me'>. */
export type Schema<N extends keyof import('./schema.d.ts').components['schemas']> =
	import('./schema.d.ts').components['schemas'][N];

/** Turns a failed call in a load function into SvelteKit's error page. */
export function loadFailed(e: unknown): never {
	if (e instanceof ApiError && e.code === 'mfa_required') error(403, 'mfa_required');
	if (e instanceof ApiError) error(e.status || 500, e.message);
	throw e;
}
