import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params }) => {
	try {
		const [app, groups, scopes, activity] = await Promise.all([
			api.get('/apps/{app}', { path: { app: params.app } }, fetch),
			api.get('/groups', {}, fetch),
			api.get('/scopes', {}, fetch),
			api.get('/audit', { query: { app: params.app, limit: 8 } }, fetch)
		]);
		return { app, groups: groups.items, scopes: scopes.items, activity: activity.items };
	} catch (e) {
		loadFailed(e);
	}
};
