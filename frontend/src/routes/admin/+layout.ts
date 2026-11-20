import { error } from '@sveltejs/kit';
import { api, loadFailed } from '#lib/api/client.ts';
import type { LayoutLoad } from './$types';

// The admin area is for Guardian administrators only; the API enforces this too, this only spares others a
// page that would fail. The overview's figures are loaded once for the whole area: the start page shows
// them, and every page needs the number of administrators for the one-administrator warning (A23).
export const load: LayoutLoad = async ({ parent, fetch, depends }) => {
	const { me } = await parent();
	if (!me.is_admin) error(403, 'The admin area is for Guardian administrators.');
	depends('guardian:overview');
	try {
		return { overview: await api.get('/overview', {}, fetch) };
	} catch (e) {
		loadFailed(e);
	}
};
