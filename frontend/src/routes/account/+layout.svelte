<script lang="ts">
	import Frame, { adminHref, type NavItem } from '#lib/components/Frame.svelte';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	const nav: NavItem[] = [
		{ href: '/account', label: 'Profile', icon: 'profile' },
		{ href: '/account/notifications', label: 'Notifications', icon: 'bell' },
		{ href: '/account/security', label: 'Security', icon: 'security' },
		{ href: '/account/sessions', label: 'Sessions', icon: 'sessions' },
		{ href: '/account/apps', label: 'Connected apps', icon: 'apps' },
		{ href: '/account/groups', label: 'Groups', icon: 'groups' },
		{ href: '/account/data', label: 'Your data', icon: 'data' }
	];
</script>

<Frame area="account" {nav} username={data.me.username} admin={adminHref(data.me)}>
	{@render children()}
</Frame>
