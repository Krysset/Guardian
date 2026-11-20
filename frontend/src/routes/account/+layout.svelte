<script lang="ts">
	import Frame, { type NavItem } from '#lib/components/Frame.svelte';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	const nav: NavItem[] = [
		{ href: '/account', label: 'Profile', icon: 'profile' },
		{ href: '/account/security', label: 'Security', icon: 'security' },
		{ href: '/account/sessions', label: 'Sessions', icon: 'sessions' },
		{ href: '/account/apps', label: 'Connected apps', icon: 'apps' },
		{ href: '/account/groups', label: 'Groups', icon: 'groups' },
		{ href: '/account/data', label: 'Your data', icon: 'data' }
	];
</script>

<Frame area="account" {nav} username={data.me.username} isAdmin={data.me.is_admin}>
	{@render children()}
</Frame>
