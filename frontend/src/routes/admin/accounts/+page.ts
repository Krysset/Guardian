import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const _pageSize = 25;

// The search, the status filter and the page (a cursor) live in the address, so a list can be shared and
// the back button works.
export const load: PageLoad = async ({ fetch, url }) => {
	const q = url.searchParams.get('q') ?? '';
	const status = url.searchParams.get('status') ?? '';
	const cursor = url.searchParams.get('cursor') ?? '';
	try {
		const page = await api.get(
			'/accounts',
			{ query: { q, status: (status || undefined) as 'active' | 'disabled' | 'must_change_password' | undefined, cursor, limit: _pageSize } },
			fetch
		);
		return { page, q, status, cursor };
	} catch (e) {
		loadFailed(e);
	}
};
