<!-- AD13 Overview: the admin area's start page. Figures only: nothing here identifies a person. -->
<script lang="ts">
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const o = $derived(data.overview);
</script>

<svelte:head><title>Overview · Guardian</title></svelte:head>

<div class="ph"><h1>Overview</h1><p>Figures only. Open a section to see who and what.</p></div>

{#snippet stats(items: [number | string, string][])}
	<div class="stats">
		{#each items as [value, label] (label)}
			<div class="stat"><b>{value}</b><span>{label}</span></div>
		{/each}
	</div>
{/snippet}

<section class="card">
	<h2 class="sec-h">Accounts</h2>
	{@render stats([
		[o.accounts.active, 'Active'],
		[o.accounts.disabled, 'Disabled'],
		[o.accounts.must_change_password, 'Must choose a new password'],
		[o.accounts.waiting_for_erasure, 'Waiting for erasure']
	])}
	<p class="links"><a href="/admin/accounts">Open accounts</a> · <a href="/admin/deleted">Deleted accounts</a></p>
</section>

<section class="card">
	<h2 class="sec-h">Groups and apps</h2>
	{@render stats([
		[o.groups, 'Groups'],
		[o.apps.enabled, 'Apps enabled'],
		[o.apps.disabled, o.apps.disabled === 1 ? 'App disabled' : 'Apps disabled']
	])}
	<p class="links"><a href="/admin/groups">Open groups</a> · <a href="/admin/apps">Open apps</a></p>
</section>

<section class="card">
	<h2 class="sec-h">Last 24 hours</h2>
	{@render stats([
		[o.last_day.sign_ins, 'Sign-ins'],
		[o.last_day.failed_sign_ins, 'Failed sign-ins'],
		[o.last_day.rate_limited, 'Rate-limited requests'],
		[o.last_day.honeypot, 'Bots caught']
	])}
	<p class="links"><a href="/admin/audit">Open the audit log</a></p>
</section>

<section class="card">
	<h2 class="sec-h">Administrators</h2>
	{@render stats([
		[o.admins.total, o.admins.total === 1 ? 'Administrator' : 'Administrators'],
		[`${o.admins.with_two_factor} of ${o.admins.total}`, 'With two-factor'],
		[o.admins.signed_in_last_day, 'Signed in today']
	])}
	{#if o.admins.permanent < o.admins.total}
		<p class="hint">{o.admins.total - o.admins.permanent} of them {o.admins.total - o.admins.permanent === 1 ? 'is' : 'are'} an administrator only until a set date.</p>
	{/if}
</section>

<style>
	.stats {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
		gap: 12px;
		margin-top: 14px;
	}
	.links {
		margin: 14px 0 0;
	}
</style>
