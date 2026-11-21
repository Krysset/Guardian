import { error } from '@sveltejs/kit';
import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

// AC6 needs the group as its owner sees it (name, description, linked apps' names) and its members.
export const load: PageLoad = async ({ fetch, params }) => {
	try {
		const [mine, members, requests] = await Promise.all([
			api.get('/me/groups', {}, fetch),
			api.get('/groups/{group}/members', { path: { group: params.group } }, fetch),
			api.get('/groups/{group}/requests', { path: { group: params.group } }, fetch)
		]);
		const group = mine.manages.find((g) => g.id === params.group);
		if (!group) error(404, 'Not found');
		return { group, members: members.items, requests: requests.items };
	} catch (e) {
		loadFailed(e);
	}
};
