import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { groups: await api.get('/me/groups', {}, fetch) };
	} catch (e) {
		loadFailed(e);
	}
};
