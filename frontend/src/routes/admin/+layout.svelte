<script lang="ts">
	import Frame, { adminHref, type NavItem } from '#lib/components/Frame.svelte';
	import Icon from '#lib/components/Icon.svelte';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();

	// App admins see only their apps.
	const nav: NavItem[] = $derived(
		data.me.is_admin
			? [
					{ href: '/admin', label: 'Overview', icon: 'overview' },
					{ href: '/admin/accounts', label: 'Accounts', icon: 'profile' },
					{ href: '/admin/groups', label: 'Groups', icon: 'groups' },
					{ href: '/admin/apps', label: 'Apps', icon: 'apps' },
					{ href: '/admin/audit', label: 'Audit log', icon: 'audit' },
					{ href: '/admin/deleted', label: 'Deleted accounts', icon: 'deleted' }
				]
			: [{ href: '/admin/apps', label: 'Your apps', icon: 'apps' }]
	);

	// A23: with one administrator, losing that account loses the admin area.
	const alone = $derived(data.overview !== undefined && data.overview.admins.total <= 1);
</script>

{#snippet warning()}
	{#if alone}
		<div class="warning" role="status">
			<Icon name="warning" />
			<span><strong>Guardian has only one administrator.</strong> Add a second so the admin area can't be lost with one account.</span>
			<a href="/admin/groups">Add an administrator</a>
		</div>
	{/if}
{/snippet}

<Frame area="admin" {nav} username={data.me.username} admin={adminHref(data.me)} banner={warning}>
	{@render children()}
</Frame>

<style>
	.warning {
		display: flex;
		gap: 12px;
		align-items: center;
		justify-content: center;
		flex-wrap: wrap;
		padding: 10px 28px;
		background: var(--warnbg);
		color: var(--warn);
		border-bottom: 1px solid var(--line);
		font-size: 14px;
	}
	.warning a {
		color: inherit;
		font-weight: 600;
	}
</style>
