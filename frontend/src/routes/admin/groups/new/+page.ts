import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

// The groups (owner choices, and keys already taken) and the apps (for a single-app group). With ?copy=<id>
// the page copies that group (A29).
export const load: PageLoad = async ({ fetch, url }) => {
	try {
		const copyOf = url.searchParams.get('copy');
		const [groups, apps, source] = await Promise.all([
			api.get('/groups', {}, fetch),
			api.get('/apps', {}, fetch),
			copyOf ? api.get('/groups/{group}', { path: { group: copyOf } }, fetch) : Promise.resolve(undefined)
		]);
		return { groups: groups.items, apps: apps.items, source };
	} catch (e) {
		loadFailed(e);
	}
};
