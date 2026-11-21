import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { home: await api.get('/me/home', {}, fetch) };
	} catch (e) {
		loadFailed(e);
	}
};
