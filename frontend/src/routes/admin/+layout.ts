import { error } from '@sveltejs/kit';
import type { LayoutLoad } from './$types';

// The admin area is for Guardian administrators only. The API enforces this too; this only spares others a
// page that would fail.
export const load: LayoutLoad = async ({ parent }) => {
	const { me } = await parent();
	if (!me.is_admin) error(403, 'The admin area is for Guardian administrators.');
};
