<!-- AD8 App: what to copy into the app (client id, discovery URL, issuer), its settings, who may sign in, the
     secret (rotated with a grace period, shown once in AD10), recent activity, and disable or delete. -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError, type Schema } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import AccessFields from '#lib/components/AccessFields.svelte';
	import AppLogo from '#lib/components/AppLogo.svelte';
	import AppSettings, { type AppSettingsValue } from '#lib/components/AppSettings.svelte';
	import CopyField from '#lib/components/CopyField.svelte';
	import SecretDialog from '#lib/components/SecretDialog.svelte';
	import UriList from '#lib/components/UriList.svelte';
	import { eventWords } from '#lib/events.ts';
	import { formatWhen, messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const app = $derived(data.app);
	const name = $derived(app.pretty_name);
	const issuer = location.origin;
	const confidential = $derived(app.client_type === 'confidential');

	type Editable = AppSettingsValue & { pretty_name: string; redirect_uris: string[] };
	const fromApp = (a: Schema<'App'>): Editable => ({
		pretty_name: a.pretty_name,
		description: a.description,
		logo_url: a.logo_url ?? '',
		homepage_url: a.homepage_url ?? '',
		redirect_uris: [...a.redirect_uris],
		post_logout_redirect_uris: [...a.post_logout_redirect_uris],
		backchannel_logout_uri: a.backchannel_logout_uri ?? '',
		is_first_party: a.is_first_party,
		access_token_ttl_seconds: a.access_token_ttl_seconds,
		scopes: [...(a.scopes ?? ['openid'])],
		require_mfa: a.require_mfa ?? false
	});
	const accessOf = (a: Schema<'App'>) => ({ rule: a.access_rule, groupIds: [...a.group_ids], machine: a.grant_types.includes('client_credentials') });

	// svelte-ignore state_referenced_locally
	let form = $state(fromApp(data.app));
	// svelte-ignore state_referenced_locally
	let access = $state(accessOf(data.app));
	// svelte-ignore state_referenced_locally
	let shownId = data.app.id;
	$effect(() => {
		if (data.app.id !== shownId) {
			shownId = data.app.id;
			form = fromApp(data.app);
			access = accessOf(data.app);
			note = null;
		}
	});

	let note = $state<{ section: string; ok: boolean; text: string } | null>(null);
	const say = (section: string, ok: boolean, text: string) => (note = { section, ok, text });

	async function saveSettings(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		if (!form.pretty_name.trim()) return say('settings', false, 'The display name cannot be empty.');
		if (!form.redirect_uris.length) return say('settings', false, 'Keep at least one redirect URI.');
		try {
			const updated = await api.patch('/apps/{app}', {
				path: { app: app.id },
				body: { ...form, pretty_name: form.pretty_name.trim(), description: form.description.trim() }
			});
			form = fromApp(updated);
			say('settings', true, 'Saved.');
			await refreshAll();
		} catch (e) {
			say('settings', false, messageOf(e));
		}
	}

	async function saveAccess(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		try {
			const updated = await api.put('/apps/{app}/access', {
				path: { app: app.id },
				body: { access_rule: access.rule, group_ids: access.groupIds, ...(confidential ? { machine_api: access.machine } : {}) }
			});
			access = accessOf(updated);
			say('access', true, 'Saved.');
			await refreshAll();
		} catch (e) {
			say('access', false, e instanceof ApiError && e.code === 'group_bound' ? 'One of the groups is bound to another app.' : messageOf(e));
		}
	}

	// Credentials
	let grace = $state(3600);
	let secret = $state<{ value: string; until: string | null } | null>(null);

	async function rotate() {
		note = null;
		if (!(await askConfirm({ title: `Create a new secret for ${name}?`, message: grace ? 'The old secret keeps working for the time you chose, so you can update the app first.' : `The old secret stops working at once: ${name} cannot sign people in until it has the new one.`, confirm: 'Create a new secret', danger: !grace }))) return;
		try {
			const r = await api.post('/apps/{app}/secret', { path: { app: app.id }, body: { grace_seconds: grace } });
			secret = { value: r.client_secret, until: grace ? new Date(Date.now() + grace * 1000).toISOString() : null };
		} catch (e) {
			say('credentials', false, messageOf(e));
		}
	}

	async function setEnabled(enabled: boolean) {
		note = null;
		if (!enabled && !(await askConfirm({ title: `Disable ${name}?`, message: 'Nobody can sign in to it or refresh their tokens until you enable it again.', confirm: 'Disable', danger: true }))) return;
		try {
			await api.patch('/apps/{app}', { path: { app: app.id }, body: { enabled } });
			await refreshAll();
		} catch (e) {
			say('danger', false, messageOf(e));
		}
	}

	async function remove() {
		note = null;
		if (!(await askConfirm({ title: `Delete ${name}?`, message: 'Its secrets, tokens and consents are removed, and nobody can sign in to it. This cannot be undone.', confirm: 'Delete', danger: true, typeToConfirm: app.name }))) return;
		try {
			await api.delete('/apps/{app}', { path: { app: app.id } });
			await refreshAll();
			await goto('/admin/apps');
		} catch (e) {
			say('danger', false, messageOf(e));
		}
	}
</script>

<svelte:head><title>{name} · Guardian</title></svelte:head>

{#snippet message(section: string)}
	{#if note?.section === section}<p class={note.ok ? 'ok-msg msg' : 'err-msg msg'} role={note.ok ? 'status' : 'alert'}>{note.text}</p>{/if}
{/snippet}

<div class="ph">
	<p class="crumb"><a href="/admin/apps">Apps</a> / {name}</p>
	<div class="title">
		<AppLogo name={name} logo={app.logo_url} size={52} />
		<div>
			<h1>{name}</h1>
			<div class="badges">
				{#if app.enabled}<span class="badge ok">Enabled</span>{:else}<span class="badge mute">Disabled</span>{/if}
				<span class="badge">{confidential ? 'With a secret' : 'Without a secret'}</span>
				<span class="badge">{app.access_rule === 'anyone' ? 'Anyone with an account' : 'Linked groups only'}</span>
			</div>
		</div>
	</div>
</div>

<section class="card">
	<h2 class="sec-h">Setup</h2>
	<p class="hint intro">Copy these into {name}'s OpenID Connect settings.</p>
	<div class="grid2">
		<CopyField label="Client id" value={app.client_id} />
		<CopyField label="Issuer" value={issuer} />
		<div class="wide"><CopyField label="Discovery URL" value="{issuer}/.well-known/openid-configuration" /></div>
	</div>
</section>

<form class="card" onsubmit={saveSettings} novalidate>
	<h2 class="sec-h">Settings</h2>
	<p class="hint intro">The name <code>{app.name}</code> never changes.</p>
	<div class="grid2">
		<div><label class="lbl" for="pn">Display name</label><input class="in" id="pn" maxlength="128" bind:value={form.pretty_name} /></div>
		<div></div>
		<div class="wide"><UriList id="ru" label="Redirect URIs" bind:uris={form.redirect_uris} required hint="Where {name} receives people after they sign in." /></div>
	</div>
	<div class="more"><AppSettings bind:value={form} scopes={data.scopes} appName={name} /></div>
	{@render message('settings')}
	<div class="end"><button class="btn" type="submit">Save settings</button></div>
</form>

<form class="card" onsubmit={saveAccess} novalidate>
	<h2 class="sec-h">Access</h2>
	<p class="hint intro">Who may sign in to {name}, and which groups it is told about.</p>
	<AccessFields bind:rule={access.rule} bind:groupIds={access.groupIds} groups={data.groups} appId={app.id} appName={name} />
	{#if confidential}
		<label class="switch">
			<span><strong>Machine API</strong><span class="hint block">{name} may read its linked groups and their members with its own credentials.</span></span>
			<input type="checkbox" bind:checked={access.machine} />
		</label>
	{/if}
	{@render message('access')}
	<div class="end"><button class="btn" type="submit">Save access</button></div>
</form>

{#if confidential}
	<section class="card">
		<h2 class="sec-h">Credentials</h2>
		<p class="hint intro">The secret is only shown when it is created.</p>
		<div class="rotate">
			<div>
				<label class="lbl" for="gr">Keep the old secret working for</label>
				<select class="in" id="gr" bind:value={grace}>
					<option value={0}>No time: stop it now</option>
					<option value={3600}>1 hour</option>
					<option value={86400}>1 day</option>
					<option value={604800}>7 days</option>
				</select>
			</div>
			<button class="btn" type="button" onclick={rotate}>Create a new secret</button>
		</div>
		{@render message('credentials')}
	</section>
{/if}

<section class="card">
	<div class="split"><h2 class="sec-h">Recent activity</h2><a href="/admin/audit?app={app.id}">Open in the audit log</a></div>
	{#if data.activity.length}
		<div class="scroll list">
			<table class="tbl">
				<thead><tr><th>When</th><th>Event</th><th>Who</th></tr></thead>
				<tbody>
					{#each data.activity as e (e.id)}
						<tr><td>{formatWhen(e.occurred_at)}</td><td>{eventWords(e.event_type)}</td><td>{e.actor_username || (e.actor_account_id ? 'An erased account' : name)}</td></tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="hint">Nothing yet.</p>
	{/if}
</section>

<section class="card danger-card">
	<h2 class="sec-h">Danger zone</h2>
	{@render message('danger')}
	<div class="rows">
		<div class="row">
			{#if app.enabled}
				<span><strong>Disable {name}</strong><span class="hint block">Nobody can sign in or refresh until you enable it again.</span></span>
				<button class="btn danger" type="button" onclick={() => setEnabled(false)}>Disable</button>
			{:else}
				<span><strong>Enable {name}</strong><span class="hint block">People who may sign in to it can do so again.</span></span>
				<button class="btn" type="button" onclick={() => setEnabled(true)}>Enable</button>
			{/if}
		</div>
		<div class="row">
			<span><strong>Delete {name}</strong><span class="hint block">Removes its secrets, tokens and consents. You type its name to confirm.</span></span>
			<button class="btn danger" type="button" onclick={remove}>Delete</button>
		</div>
	</div>
</section>

{#if secret}
	<SecretDialog appName={name} secret={secret.value} oldUntil={secret.until} done={() => (secret = null)} />
{/if}

<style>
	.title {
		display: flex;
		align-items: center;
		gap: 16px;
		flex-wrap: wrap;
	}
	.badges {
		display: flex;
		gap: 8px;
		margin-top: 6px;
		flex-wrap: wrap;
	}
	.badge.ok {
		color: var(--ok);
	}
	.badge.mute {
		color: var(--mute);
	}
	.intro {
		margin: 0 0 18px;
	}
	.wide {
		grid-column: 1 / -1;
	}
	code {
		font: 500 14px ui-monospace, Menlo, Consolas, monospace;
	}
	.more {
		margin-top: 18px;
	}
	.msg {
		margin: 14px 0 0;
	}
	.end {
		display: flex;
		justify-content: flex-end;
		margin-top: 20px;
	}
	.switch {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 18px;
		margin-top: 20px;
		cursor: pointer;
	}
	.switch strong {
		font-weight: 600;
	}
	.switch input {
		width: 20px;
		height: 20px;
		accent-color: var(--accent);
		flex: none;
	}
	.block {
		display: block;
		margin: 0;
	}
	.rotate {
		display: flex;
		gap: 12px;
		align-items: flex-end;
		flex-wrap: wrap;
	}
	.rotate > div {
		flex: 0 1 280px;
	}
	.split {
		display: flex;
		justify-content: space-between;
		align-items: baseline;
		gap: 12px;
	}
	.list,
	.rows {
		margin-top: 14px;
	}
	.danger-card {
		border-color: var(--danger);
	}
</style>
