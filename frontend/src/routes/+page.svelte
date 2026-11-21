<!-- H0 Home: where a signed-in user lands. The apps they use and may use, what needs them, and the way to the
     account and admin areas. No personal details. -->
<script lang="ts">
	import AppLogo from '#lib/components/AppLogo.svelte';
	import Frame, { adminHref } from '#lib/components/Frame.svelte';
	import Icon from '#lib/components/Icon.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	const me = $derived(data.me);
	const home = $derived(data.home);
	const host = (url: string) => {
		try {
			return new URL(url).host;
		} catch {
			return url;
		}
	};
	const needsTwoFactor = $derived(me.mfa.required && !me.mfa.totp && !(me.mfa.security_keys ?? []).length);
	const pendingEmail = $derived(!!me.email_settings.pending);
</script>

<svelte:head><title>Home · {home.site_name}</title></svelte:head>

{#snippet tiles(apps: typeof home.connected)}
	<div class="tiles">
		{#each apps as app (app.id)}
			<a class="tile-link" href={app.homepage_url}>
				<AppLogo name={app.display_name} logo={app.logo_url} size={44} />
				<span class="text">
					<strong>{app.display_name}</strong>
					{#if app.description}<span>{app.description}</span>{/if}
					<span class="host">{host(app.homepage_url)}</span>
				</span>
			</a>
		{/each}
	</div>
{/snippet}

<Frame area="home" username={me.username} admin={adminHref(me)}>
	<div class="ph"><h1>Welcome to {home.site_name}</h1><p>Your apps, and where to manage your account.</p></div>

	{#if needsTwoFactor || pendingEmail}
		<section class="card">
			<h2 class="sec-h">Needs your attention</h2>
			<div class="rows">
				{#if needsTwoFactor}
					<div class="row">
						<span><strong>Set up two-factor</strong><span class="hint block">{me.mfa.required_reason}</span></span>
						<a class="btn" href="/account/security">Set up</a>
					</div>
				{/if}
				{#if pendingEmail}
					<div class="row">
						<span><strong>Confirm your new email address</strong><span class="hint block">Open the link we sent to it.</span></span>
						<a class="btn alt" href="/account">Details</a>
					</div>
				{/if}
			</div>
		</section>
	{/if}

	{#if !home.connected.length && !home.available.length}
		<section class="card">
			<h2 class="sec-h">Apps</h2>
			<p class="empty">No apps yet. Ask an administrator for access.</p>
		</section>
	{/if}


	{#if home.connected.length}
		<section class="card">
			<h2 class="sec-h">Your connected apps</h2>
			<p class="hint intro">Apps you've signed in to. Open one; you're already signed in.</p>
			{@render tiles(home.connected)}
			<p class="more"><a href="/account/apps">See what each app can see, or remove access</a></p>
		</section>
	{/if}

	{#if home.available.length}
		<section class="card">
			<h2 class="sec-h">Available apps</h2>
			<p class="hint intro">Apps you have access to.</p>
			{@render tiles(home.available)}
			<p class="hint more">You may sign in to these but haven't yet. Ask an administrator if an app is missing.</p>
		</section>
	{/if}

	<section class="card">
		<h2 class="sec-h">Manage</h2>
		<div class="tiles manage">
			<a class="tile-link" href="/account">
				<Icon name="profile" />
				<span class="text"><strong>Your account</strong><span>Profile, password, two-factor, sessions and your data.</span></span>
			</a>
			{#if me.is_admin}
				<a class="tile-link" href="/admin">
					<Icon name="shield" />
					<span class="text"><strong>Admin area</strong><span>Accounts, groups, apps and the audit log.</span></span>
				</a>
			{:else if me.app_admin}
				<a class="tile-link" href="/admin/apps">
					<Icon name="apps" />
					<span class="text"><strong>Your apps</strong><span>The apps you are an admin of: settings, access and secret.</span></span>
				</a>
			{/if}
		</div>
	</section>
</Frame>

<style>
	.rows {
		margin-top: 14px;
	}
	.block {
		display: block;
		margin: 0;
	}
	.intro {
		margin: 0 0 18px;
	}
	.empty {
		margin: 14px 0 0;
		padding: 24px;
		text-align: center;
		border: 1px dashed var(--line);
		border-radius: 8px;
		color: var(--mute);
	}
	.tiles {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
		gap: 14px;
	}
	.manage {
		margin-top: 14px;
	}
	.tile-link {
		display: flex;
		gap: 14px;
		align-items: flex-start;
		padding: 18px;
		border-radius: 10px;
		border: 1px solid var(--line);
		background: var(--bg);
		text-decoration: none;
		color: var(--ink);
	}
	.tile-link:hover {
		border-color: var(--accent);
		color: var(--ink);
	}
	.tile-link > :global(svg) {
		flex: none;
		color: var(--accent);
		margin-top: 2px;
	}
	.text {
		display: block;
		min-width: 0;
	}
	.text strong {
		display: block;
		font-weight: 600;
	}
	.text span {
		display: block;
		font-size: 14px;
		color: var(--mute);
	}
	.text .host {
		font-size: 13px;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.more {
		margin: 14px 0 0;
		font-size: 14px;
	}
</style>
