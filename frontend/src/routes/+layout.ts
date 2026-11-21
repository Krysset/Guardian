import { api } from '#lib/api/client.ts';
import type { LayoutLoad } from './$types';

// A single-page app: every page is rendered in the browser from the fallback page.
export const ssr = false;
export const prerender = false;

// Every page needs the signed-in account: its username for the top bar, and whether it is an administrator.
// Without a session the API client sends the browser to the sign-in page.
export const load: LayoutLoad = async ({ fetch, url }) => {
	const me = await api.get('/me', {}, fetch);
	if (me.must_change_password) {
		// An administrator set a temporary password: the account gets nothing until it chooses its own.
		location.assign('/password?return_to=' + encodeURIComponent(url.pathname + url.search));
		await new Promise(() => {});
	}
	return { me };
};
