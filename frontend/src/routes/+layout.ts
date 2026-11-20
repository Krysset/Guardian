import { api } from '#lib/api/client.ts';
import type { LayoutLoad } from './$types';

// A single-page app: every page is rendered in the browser from the fallback page.
export const ssr = false;
export const prerender = false;

// Every page needs the signed-in account: its username for the top bar, and whether it is an administrator.
// Without a session the API client sends the browser to the sign-in page.
export const load: LayoutLoad = async ({ fetch }) => {
	const me = await api.get('/me', {}, fetch);
	return { me };
};
