import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { sessions: (await api.get('/me/sessions', {}, fetch)).items };
	} catch (e) {
		loadFailed(e);
	}
};
