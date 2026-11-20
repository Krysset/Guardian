import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

// The groups (owner choices, and keys already taken) and the apps (for a single-app group).
export const load: PageLoad = async ({ fetch }) => {
	try {
		const [groups, apps] = await Promise.all([api.get('/groups', {}, fetch), api.get('/apps', {}, fetch)]);
		return { groups: groups.items, apps: apps.items };
	} catch (e) {
		loadFailed(e);
	}
};
