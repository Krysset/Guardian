import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		const [groups, scopes, apps] = await Promise.all([api.get('/groups', {}, fetch), api.get('/scopes', {}, fetch), api.get('/apps', {}, fetch)]);
		return { groups: groups.items, scopes: scopes.items, names: apps.items.map((a) => a.name) };
	} catch (e) {
		loadFailed(e);
	}
};
