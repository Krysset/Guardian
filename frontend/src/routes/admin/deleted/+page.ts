import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch }) => {
	try {
		return { deleted: (await api.get('/accounts/deleted', {}, fetch)).items ?? [] };
	} catch (e) {
		loadFailed(e);
	}
};
