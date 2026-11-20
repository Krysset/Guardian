import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params }) => {
	try {
		const path = { group: params.group };
		const [group, members, groups, apps] = await Promise.all([
			api.get('/groups/{group}', { path }, fetch),
			api.get('/groups/{group}/members', { path }, fetch),
			api.get('/groups', {}, fetch),
			api.get('/apps', {}, fetch)
		]);
		return { group, members: members.items, groups: groups.items, apps: apps.items };
	} catch (e) {
		loadFailed(e);
	}
};
