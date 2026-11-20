<script lang="ts">
	import Frame, { type NavItem } from '#lib/components/Frame.svelte';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	const nav: NavItem[] = [
		{ href: '/admin', label: 'Overview', icon: 'overview' },
		{ href: '/admin/accounts', label: 'Accounts', icon: 'profile' },
		{ href: '/admin/groups', label: 'Groups', icon: 'groups' },
		{ href: '/admin/apps', label: 'Apps', icon: 'apps' },
		{ href: '/admin/audit', label: 'Audit log', icon: 'audit' },
		{ href: '/admin/deleted', label: 'Deleted accounts', icon: 'deleted' }
	];
</script>

<Frame area="admin" {nav} username={data.me.username} isAdmin>
	{@render children()}
</Frame>
