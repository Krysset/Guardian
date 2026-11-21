import { api, ApiError, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const _pageSize = 50;

// The filters and the page (a cursor) live in the address, so a view of the log can be shared and the back
// button works. ?app= comes from an app's page (AD8).
export const load: PageLoad = async ({ fetch, url }) => {
	const event = url.searchParams.get('event') ?? '';
	const username = url.searchParams.get('username') ?? '';
	const app = url.searchParams.get('app') ?? '';
	const cursor = url.searchParams.get('cursor') ?? '';
	const filters = { event, username, app, cursor };
	try {
		const [page, appName] = await Promise.all([
			api
				.get('/audit', { query: { event: event || undefined, username: username || undefined, app: app || undefined, cursor: cursor || undefined, limit: _pageSize } }, fetch)
				.catch((e) => {
					if (e instanceof ApiError && e.code === 'account_not_found') return null;
					throw e;
				}),
			app
				? api
						.get('/apps/{app}', { path: { app } }, fetch)
						.then((a) => a.pretty_name)
						.catch((e) => {
							if (e instanceof ApiError && e.status === 404) return 'A deleted app';
							throw e;
						})
				: Promise.resolve('')
		]);
		return { ...filters, appName, page: page ?? { items: [], next_cursor: null }, unknownUser: page === null };
	} catch (e) {
		loadFailed(e);
	}
};
