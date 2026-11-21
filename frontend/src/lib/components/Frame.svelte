<!-- F2, the management UI frame: the top bar (logo to Home, the area switch for administrators and app admins, the signed-in
     username, Sign out), the area's navigation, and the page. Home has no area navigation. The admin area
     passes its warning (A23) as `banner`. -->
<script lang="ts" module>
	import type { IconName } from './Icon.svelte';

	export type NavItem = { href: string; label: string; icon: IconName };

	// Where the Admin link goes: the admin area for administrators, their apps for app admins, nowhere
	// (no area switch) for everyone else.
	export function adminHref(me: { is_admin: boolean; app_admin: boolean }): string | undefined {
		return me.is_admin ? '/admin' : me.app_admin ? '/admin/apps' : undefined;
	}
</script>

<script lang="ts">
	import type { Snippet } from 'svelte';
	import { page } from '$app/state';
	import Icon from './Icon.svelte';

	let {
		area,
		nav = [],
		username,
		admin,
		banner,
		children
	}: {
		area: 'home' | 'account' | 'admin';
		nav?: NavItem[];
		username: string;
		admin: string | undefined;
		banner?: Snippet;
		children: Snippet;
	} = $props();

	const areaLabel = $derived(area === 'admin' ? 'Admin' : 'Account');

	// The area's start page is current only on itself; other items also on the pages below them.
	function current(href: string): boolean {
		const path = page.url.pathname.replace(/\/$/, '');
		return href === `/${area}` ? path === href : path === href || path.startsWith(href + '/');
	}
</script>

<header class="top">
	<a class="brand" href="/">
		<img src="/static/favicon.svg" alt="" width="28" height="28" />
		<span>Guardian</span>
	</a>
	{#if admin}
		<nav class="area" aria-label="Area">
			<a href="/account" aria-current={area === 'account' ? 'page' : undefined}>Account</a>
			<a href={admin} aria-current={area === 'admin' ? 'page' : undefined}>Admin</a>
		</nav>
	{/if}
	<span class="who">
		<span>Signed in as <strong>{username}</strong></span>
		<a class="btn alt signout" href="/logout" data-sveltekit-reload>Sign out</a>
	</span>
</header>

{@render banner?.()}

<div class="wrap">
	{#if nav.length}
		<nav class="side" aria-label={areaLabel}>
			{#each nav as item (item.href)}
				<a class="nav" href={item.href} aria-current={current(item.href) ? 'page' : undefined}>
					<Icon name={item.icon} />{item.label}
				</a>
			{/each}
		</nav>
	{/if}
	<main class="main" class:narrow={!nav.length}>
		{@render children()}
	</main>
</div>

<style>
	.top {
		display: flex;
		align-items: center;
		gap: 20px;
		flex-wrap: wrap;
		padding: 0 28px;
		min-height: 60px;
		position: sticky;
		top: 0;
		z-index: 2;
		background: var(--glass);
		-webkit-backdrop-filter: var(--blur);
		backdrop-filter: var(--blur);
		border-bottom: 1px solid var(--gline);
		box-shadow: 0 6px 24px -14px rgba(10, 30, 30, 0.5);
	}
	.brand {
		display: flex;
		align-items: center;
		gap: 10px;
		text-decoration: none;
		color: var(--ink);
		font: 600 18px Figtree, system-ui, sans-serif;
	}
	.area {
		display: flex;
		gap: 4px;
	}
	.area a {
		padding: 6px 12px;
		border-radius: 6px;
		text-decoration: none;
		color: var(--mute);
		font-weight: 500;
		font-size: 15px;
	}
	.area a:hover {
		color: var(--ink);
	}
	.area a[aria-current='page'] {
		background: var(--sel);
		color: var(--ink);
	}
	.who {
		margin-left: auto;
		display: flex;
		align-items: center;
		gap: 14px;
		font-size: 14px;
	}
	.signout {
		height: 34px;
		padding: 0 12px;
	}
	.wrap {
		max-width: 1180px;
		margin: 0 auto;
		padding: 28px;
		display: flex;
		flex-wrap: wrap;
		gap: 28px;
		box-sizing: border-box;
	}
	.side {
		flex: 0 0 232px;
		max-width: 232px;
		align-self: flex-start;
		display: flex;
		flex-direction: column;
		gap: 2px;
		padding: 10px;
		box-sizing: border-box;
		border-radius: 10px;
		background: var(--glass);
		-webkit-backdrop-filter: var(--blur);
		backdrop-filter: var(--blur);
		border: 1px solid var(--gline);
	}
	.nav {
		display: flex;
		align-items: center;
		gap: 12px;
		padding: 9px 12px;
		border-radius: 6px;
		color: var(--ink);
		text-decoration: none;
		font-weight: 500;
		font-size: 15px;
		white-space: nowrap;
	}
	.nav:hover {
		background: color-mix(in srgb, var(--accent) 10%, transparent);
		color: var(--ink);
	}
	.nav[aria-current='page'] {
		background: var(--sel);
		color: var(--link);
		font-weight: 600;
	}
	.nav[aria-current='page']::after {
		content: '';
		margin-left: auto;
		width: 7px;
		height: 7px;
		transform: rotate(45deg);
		background: var(--hl);
	}
	.main {
		flex: 999 1 560px;
		min-width: 0;
		display: flex;
		flex-direction: column;
		gap: 20px;
	}
	.main.narrow {
		max-width: 960px;
		margin: 0 auto;
	}
	@media (max-width: 760px) {
		.side {
			flex: 1 1 100%;
			max-width: none;
			flex-direction: row;
			flex-wrap: wrap;
		}
		.wrap {
			padding: 16px;
		}
		.top {
			padding: 10px 16px;
		}
		.who {
			margin-left: 0;
		}
	}
</style>
