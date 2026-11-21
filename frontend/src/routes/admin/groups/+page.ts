import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

// Groups and apps together: the list names each group's owner group and linked apps.
export const load: PageLoad = async ({ fetch }) => {
	try {
		const [groups, apps] = await Promise.all([api.get('/groups', {}, fetch), api.get('/apps', {}, fetch)]);
		return { groups: groups.items, apps: apps.items };
	} catch (e) {
		loadFailed(e);
	}
};
