import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { notifications: await api.get('/me/notifications', {}, fetch) };
	} catch (e) {
		loadFailed(e);
	}
};
