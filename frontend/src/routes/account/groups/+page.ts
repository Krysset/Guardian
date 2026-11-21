import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		const [groups, requests] = await Promise.all([api.get('/me/groups', {}, fetch), api.get('/me/group-requests', {}, fetch)]);
		return { groups, requests };
	} catch (e) {
		loadFailed(e);
	}
};
