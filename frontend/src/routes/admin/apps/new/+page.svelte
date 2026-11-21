<!-- AD9 New app: name and display name, type (with or without a secret), redirect URIs, who may sign in, and
     the other settings folded away. An app with a secret shows it once (AD10), then opens its page (AD8). -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import AccessFields from '#lib/components/AccessFields.svelte';
	import AppSettings, { type AppSettingsValue } from '#lib/components/AppSettings.svelte';
	import SecretDialog from '#lib/components/SecretDialog.svelte';
	import UriList from '#lib/components/UriList.svelte';
	import { messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let name = $state('');
	let displayName = $state('');
	let type = $state<'confidential' | 'public'>('confidential');
	let redirects = $state<string[]>([]);
	let rule = $state<'groups' | 'anyone'>('groups');
	let groupIds = $state<string[]>([]);
	let settings = $state<AppSettingsValue>({
		description: '',
		logo_url: '',
		homepage_url: '',
		post_logout_redirect_uris: [],
		backchannel_logout_uri: '',
		is_first_party: false,
		access_token_ttl_seconds: 300,
		scopes: ['openid', 'profile', 'email', 'groups'],
		require_mfa: false,
		signing_alg: 'RS256'
	});
	let errors = $state<{ name?: string; display?: string; redirects?: string; form?: string }>({});
	let busy = $state(false);
	let created = $state<{ id: string; name: string; secret: string } | null>(null);

	const nameOk = $derived(/^[a-z0-9][a-z0-9_-]{1,62}$/.test(name));
	const taken = $derived(data.names.includes(name));
	const shownName = $derived(displayName.trim() || 'the app');

	async function register(event: SubmitEvent) {
		event.preventDefault();
		const e: typeof errors = {};
		if (!nameOk) e.name = 'Use 2–63 lowercase letters, digits, dashes or underscores, starting with a letter or digit.';
		else if (taken) e.name = 'An app already has that name.';
		if (!displayName.trim()) e.display = 'Give the app a name people will see.';
		if (!redirects.length) e.redirects = 'Add at least one redirect URI.';
		errors = e;
		if (Object.keys(e).length) return;
		busy = true;
		const optional = (v: string) => (v.trim() ? v.trim() : undefined);
		try {
			const r = await api.post('/apps', {
				body: {
					name,
					pretty_name: displayName.trim(),
					client_type: type,
					redirect_uris: redirects,
					access_rule: rule,
					group_ids: groupIds,
					description: optional(settings.description),
					logo_url: optional(settings.logo_url),
					homepage_url: optional(settings.homepage_url),
					post_logout_redirect_uris: settings.post_logout_redirect_uris,
					backchannel_logout_uri: optional(settings.backchannel_logout_uri),
					is_first_party: settings.is_first_party,
					access_token_ttl_seconds: settings.access_token_ttl_seconds,
					scopes: settings.scopes,
					require_mfa: settings.require_mfa,
					signing_alg: settings.signing_alg
				}
			});
			await refreshAll();
			if (r.client_secret) created = { id: r.app.id, name: r.app.pretty_name, secret: r.client_secret };
			else await goto(`/admin/apps/${r.app.id}`);
		} catch (err) {
			errors = err instanceof ApiError && err.status === 409 ? { name: err.message } : { form: messageOf(err) };
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>New app · Guardian</title></svelte:head>

<div class="ph"><p class="crumb"><a href="/admin/apps">Apps</a> / New</p><h1>New app</h1></div>

<form class="stack" onsubmit={register} novalidate>
	<section class="card">
		<h2 class="sec-h">About the app</h2>
		<div class="grid2 fields">
			<div>
				<label class="lbl" for="an">Name</label>
				<input class="in" id="an" bind:value={name} autocomplete="off" autocapitalize="none" spellcheck="false" aria-invalid={errors.name ? 'true' : undefined} aria-describedby="an-hint" />
				{#if errors.name}<p class="err-t" id="an-hint">{errors.name}</p>
				{:else}<p class="hint" id="an-hint">For machines: lowercase letters, digits, dashes. <strong>Never changes.</strong></p>{/if}
			</div>
			<div>
				<label class="lbl" for="adn">Display name</label>
				<input class="in" id="adn" maxlength="128" bind:value={displayName} aria-invalid={errors.display ? 'true' : undefined} />
				{#if errors.display}<p class="err-t">{errors.display}</p>{:else}<p class="hint">What people see on Home and the consent page.</p>{/if}
			</div>
		</div>
		<fieldset class="type">
			<legend class="lbl">Type</legend>
			<div class="grid2">
				<label class="radio"><input type="radio" name="ty" value="confidential" bind:group={type} /><span><strong>With a secret</strong><span class="hint block">A server-side app that can keep a secret.</span></span></label>
				<label class="radio"><input type="radio" name="ty" value="public" bind:group={type} /><span><strong>Without a secret</strong><span class="hint block">A browser or mobile app. Uses PKCE instead.</span></span></label>
			</div>
		</fieldset>
		<div class="redirects">
			<UriList id="ru" label="Redirect URIs" bind:uris={redirects} hint="Where {shownName} receives people after they sign in." />
			{#if errors.redirects}<p class="err-t" role="alert">{errors.redirects}</p>{/if}
		</div>
	</section>

	<section class="card">
		<h2 class="sec-h">Access</h2>
		<div class="fields"><AccessFields bind:rule bind:groupIds groups={data.groups} appName={shownName} /></div>
	</section>

	<details class="card">
		<summary><span class="sec-h inline">More settings</span> <span class="hint">· homepage, logo, sign-out redirects, back-channel logout, consent, two-factor, token lifetime, scopes</span></summary>
		<div class="fields"><AppSettings bind:value={settings} scopes={data.scopes} appName={shownName} /></div>
	</details>

	{#if errors.form}<p class="err-msg" role="alert">{errors.form}</p>{/if}
	<div class="actions"><a class="btn alt" href="/admin/apps">Cancel</a><button class="btn" type="submit" disabled={busy}>Register</button></div>
</form>

{#if created}
	<SecretDialog appName={created.name} secret={created.secret} done={() => goto(`/admin/apps/${created?.id}`)} />
{/if}

<style>
	.stack {
		display: flex;
		flex-direction: column;
		gap: 20px;
	}
	.stack > p {
		margin: 0;
	}
	.fields {
		margin-top: 14px;
	}
	.type {
		border: 0;
		padding: 0;
		margin: 20px 0 0;
	}
	.radio {
		display: flex;
		gap: 12px;
		align-items: flex-start;
		padding: 14px 16px;
		border: 1px solid var(--line);
		border-radius: 8px;
		cursor: pointer;
	}
	.radio:has(input:checked) {
		border-color: var(--accent);
		background: var(--sel);
	}
	.radio input {
		margin-top: 4px;
		accent-color: var(--accent);
	}
	.radio strong {
		font-weight: 600;
	}
	.block {
		display: block;
		margin: 0;
	}
	.redirects {
		margin-top: 20px;
	}
	summary {
		cursor: pointer;
	}
	.inline {
		display: inline;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
	}
</style>
