import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { apps: (await api.get('/me/apps', {}, fetch)).items };
	} catch (e) {
		loadFailed(e);
	}
};
