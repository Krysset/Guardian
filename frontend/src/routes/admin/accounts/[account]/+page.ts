import { api, loadFailed } from '#lib/api/client.ts';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ fetch, params, depends }) => {
	depends('guardian:account');
	try {
		const path = { account: params.account };
		const [account, groups, activity] = await Promise.all([
			api.get('/accounts/{account}', { path }, fetch),
			api.get('/groups', {}, fetch),
			api.get('/audit', { query: { about: params.account, limit: 8 } }, fetch)
		]);
		return { account, groups: groups.items, activity: activity.items };
	} catch (e) {
		loadFailed(e);
	}
};
