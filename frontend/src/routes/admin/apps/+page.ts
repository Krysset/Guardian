import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		const [apps, groups] = await Promise.all([api.get('/apps', {}, fetch), api.get('/groups', {}, fetch)]);
		return { apps: apps.items, groups: groups.items };
	} catch (e) {
		loadFailed(e);
	}
};
