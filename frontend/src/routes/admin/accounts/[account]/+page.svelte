<!-- AD2 Account: profile and email (masked until shown; an address set here counts as confirmed), access
     (sign out everywhere, a temporary password, two-factor reset with a reason, disable or enable), groups
     with expiry, recent activity, and delete or erase. -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError, type Schema } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import Icon from '#lib/components/Icon.svelte';
	import PasswordField from '#lib/components/PasswordField.svelte';
	import { copyText, generatePassword } from '#lib/password.ts';
	import { eventWords } from '#lib/events.ts';
	import { dateInput, endOfDay, formatDate, formatWhen, initial, maskEmail, messageOf } from '#lib/format.ts';
	import { localeOptions, zoneOptions } from '#lib/locales.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const account = $derived(data.account);
	const name = $derived(account.username);

	// What a two-factor reset removes, in words: "the authenticator app and 2 security keys".
	function twoFactorMethods(mfa: { totp?: boolean; security_keys?: unknown[] }) {
		const keys = mfa.security_keys?.length ?? 0;
		const parts = [mfa.totp ? 'the authenticator app' : '', keys === 1 ? 'one security key' : keys ? `${keys} security keys` : ''].filter(Boolean);
		return parts.join(' and ');
	}
	const path = $derived({ account: account.id });
	const today = dateInput(new Date().toISOString());

	// Messages per section, so each shows next to what it is about.
	let note = $state<{ section: string; ok: boolean; text: string } | null>(null);
	const say = (section: string, ok: boolean, text: string) => (note = { section, ok, text });
	const fail = (section: string, e: unknown) => {
		if (!(e instanceof ApiError && e.code === 'cancelled')) say(section, false, messageOf(e));
	};

	// Profile
	type Fields = { username: string; display_name: string; given_name: string; family_name: string; picture_url: string; locale: string; zoneinfo: string; email: string };
	const fromAccount = (a: Schema<'Account'>): Fields => ({
		username: a.username,
		display_name: a.display_name ?? '',
		given_name: a.given_name ?? '',
		family_name: a.family_name ?? '',
		picture_url: a.picture_url ?? '',
		locale: a.locale ?? '',
		zoneinfo: a.zoneinfo ?? '',
		email: a.email ?? ''
	});
	// svelte-ignore state_referenced_locally
	let saved = $state(fromAccount(data.account));
	// svelte-ignore state_referenced_locally
	let form = $state(fromAccount(data.account));
	let showEmail = $state(false);
	// Another account opened from this page (a link in its activity, say): start from that one.
	// svelte-ignore state_referenced_locally
	let shownId = data.account.id;
	$effect(() => {
		if (data.account.id !== shownId) {
			shownId = data.account.id;
			saved = fromAccount(data.account);
			form = fromAccount(data.account);
			showEmail = false;
			note = null;
		}
	});
	const changes = $derived(Object.fromEntries(Object.entries(form).filter(([k, v]) => v.trim() !== saved[k as keyof Fields])));
	const dirty = $derived(Object.keys(changes).length > 0);
	const locales = $derived(localeOptions(saved.locale));
	const zones = $derived(zoneOptions(saved.zoneinfo));

	async function saveProfile(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		if (!dirty) return;
		try {
			const body = Object.fromEntries(Object.entries(changes).map(([k, v]) => [k, v.trim()]));
			const updated = await api.patch('/accounts/{account}', { path, body });
			saved = fromAccount(updated);
			form = fromAccount(updated);
			say('profile', true, 'Saved.');
			await refreshAll();
		} catch (e) {
			fail('profile', e);
		}
	}

	// Access
	let tempPassword = $state('');
	let tempPassword2 = $state('');
	let showTemp = $state(false);
	let generated = $state('');

	async function generate() {
		tempPassword = tempPassword2 = generatePassword();
		showTemp = true;
		generated = (await copyText(tempPassword)) ? 'Generated and copied.' : 'Generated. Copy it from the field.';
	}
	let reason = $state('');

	async function signOutEverywhere() {
		note = null;
		if (!(await askConfirm({ title: `Sign ${name} out everywhere?`, message: 'Every session and app token ends. The account stays enabled.', confirm: 'Sign out everywhere' }))) return;
		try {
			await api.delete('/accounts/{account}/sessions', { path });
			say('access', true, `${name} is signed out everywhere.`);
			await refreshAll();
		} catch (e) {
			fail('access', e);
		}
	}

	async function setPassword(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		if (tempPassword.length < 10) return say('access', false, 'Use at least 10 characters.');
		if (tempPassword !== tempPassword2) return say('access', false, 'The passwords do not match.');
		try {
			await api.put('/accounts/{account}/password', { path, body: { new_password: tempPassword } });
			tempPassword = tempPassword2 = generated = '';
			showTemp = false;
			say('access', true, `The temporary password is set. ${name} is signed out everywhere and must choose a new one at the next sign-in.`);
			await refreshAll();
		} catch (e) {
			fail('access', e);
		}
	}

	async function resetTwoFactor(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		if (reason.trim().length < 3) return say('access', false, 'Give a reason; the user is told it.');
		if (!(await askConfirm({ title: `Reset ${name}'s two-factor?`, message: `${twoFactorMethods(account.mfa)[0].toUpperCase()}${twoFactorMethods(account.mfa).slice(1)} and the recovery codes are removed, and the user is emailed the reason.`, confirm: 'Reset two-factor', danger: true }))) return;
		try {
			await api.post('/accounts/{account}/mfa/reset', { path, body: { reason: reason.trim() } });
			reason = '';
			say('access', true, `Two-factor is reset. ${name} sets it up again at the next sign-in if it is required.`);
			await refreshAll();
		} catch (e) {
			fail('access', e);
		}
	}

	async function setStatus(status: 'active' | 'disabled') {
		note = null;
		if (status === 'disabled' && !(await askConfirm({ title: `Disable ${name}?`, message: `${name} is signed out everywhere and cannot sign in until enabled again.`, confirm: 'Disable', danger: true }))) return;
		try {
			await api.patch('/accounts/{account}', { path, body: { status } });
			say('access', true, status === 'disabled' ? `${name} is disabled.` : `${name} is enabled.`);
			await refreshAll();
		} catch (e) {
			if (e instanceof ApiError && e.code === 'last_admin') say('access', false, 'This is the last administrator whose membership does not expire. Make someone else an administrator first.');
			else fail('access', e);
		}
	}

	// Groups
	let addGroup = $state('');
	let addExpires = $state('');
	let editing = $state<string | null>(null);
	let editDate = $state('');
	const memberOf = $derived(new Set(account.groups.map((g) => g.group_id)));
	const addable = $derived(data.groups.filter((g) => !memberOf.has(g.id)));
	const groupBound = (id: string) => data.groups.find((g) => g.id === id)?.single_app;

	async function addToGroup(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		if (!addGroup) return say('groups', false, 'Choose a group.');
		try {
			await api.put('/groups/{group}/members/{account}', { path: { group: addGroup, account: account.id }, body: addExpires ? { expires_at: endOfDay(addExpires) } : {} });
			addGroup = addExpires = '';
			await refreshAll();
		} catch (e) {
			fail('groups', e);
		}
	}

	async function saveExpiry(group: string) {
		note = null;
		try {
			await api.put('/groups/{group}/members/{account}', { path: { group, account: account.id }, body: editDate ? { expires_at: endOfDay(editDate) } : {} });
			editing = null;
			await refreshAll();
		} catch (e) {
			fail('groups', e);
		}
	}

	async function removeFromGroup(group: string, groupName: string) {
		note = null;
		if (!(await askConfirm({ title: `Remove ${name} from ${groupName}?`, confirm: 'Remove', danger: true }))) return;
		try {
			await api.delete('/groups/{group}/members/{account}', { path: { group, account: account.id } });
			await refreshAll();
		} catch (e) {
			if (e instanceof ApiError && e.code === 'last_admin') say('groups', false, 'This is the last administrator whose membership does not expire.');
			else fail('groups', e);
		}
	}

	// Delete and erase
	async function remove() {
		note = null;
		if (!(await askConfirm({ title: `Delete ${name}?`, message: 'The account is signed out everywhere and erased after 30 days. You can restore it until then.', confirm: 'Delete', danger: true, typeToConfirm: name }))) return;
		try {
			await api.delete('/accounts/{account}', { path });
			await refreshAll();
			await goto('/admin/deleted');
		} catch (e) {
			if (e instanceof ApiError && e.code === 'last_admin') say('delete', false, 'This is the last administrator. Make someone else an administrator first.');
			else fail('delete', e);
		}
	}

	async function erase() {
		note = null;
		if (!(await askConfirm({ title: `Erase ${name} now?`, message: 'The account and what it owns are deleted at once, without the 30 days. This cannot be undone.', confirm: 'Erase now', danger: true, typeToConfirm: name }))) return;
		try {
			await api.post('/accounts/{account}/erase', { path, body: { username: name } });
			await refreshAll();
			await goto('/admin/accounts');
		} catch (e) {
			if (e instanceof ApiError && e.code === 'last_admin') say('delete', false, 'This is the last administrator. Make someone else an administrator first.');
			else fail('delete', e);
		}
	}
</script>

<svelte:head><title>{name} · Guardian</title></svelte:head>

{#snippet message(section: string)}
	{#if note?.section === section}<p class={note.ok ? 'ok-msg msg' : 'err-msg msg'} role={note.ok ? 'status' : 'alert'}>{note.text}</p>{/if}
{/snippet}

<div class="ph">
	<p class="crumb"><a href="/admin/accounts">Accounts</a> / {name}</p>
	<div class="title">
		<span class="av big" aria-hidden="true">{initial(account.display_name || name)}</span>
		<div>
			<h1>{name}</h1>
			<div class="badges">
				{#if account.status === 'active'}<span class="badge ok">Active</span>{:else}<span class="badge mute">Disabled</span>{/if}
				{#if account.must_change_password}<span class="badge hl">Must choose a new password</span>{/if}
				{#if account.is_admin}<span class="badge">Administrator</span>{/if}
			</div>
		</div>
	</div>
	<p class="meta">Created {formatDate(account.created_at)} · last sign-in {account.last_login_at ? formatWhen(account.last_login_at).toLowerCase() : 'never'}</p>
</div>

<form class="card" onsubmit={saveProfile} novalidate>
	<h2 class="sec-h">Profile</h2>
	<div class="grid2 fields">
		<div><label class="lbl" for="dn">Display name</label><input class="in" id="dn" maxlength="128" bind:value={form.display_name} /></div>
		<div><label class="lbl" for="un">Username</label><input class="in" id="un" bind:value={form.username} autocapitalize="none" spellcheck="false" /></div>
		<div><label class="lbl" for="gn">Given name</label><input class="in" id="gn" maxlength="128" bind:value={form.given_name} /></div>
		<div><label class="lbl" for="fn">Family name</label><input class="in" id="fn" maxlength="128" bind:value={form.family_name} placeholder="Optional" /></div>
		<div>
			<label class="lbl" for="em">Email</label>
			{#if showEmail || !saved.email}
				<input class="in" id="em" type="email" bind:value={form.email} placeholder="name@example.com" />
			{:else}
				<div class="mask">
					<span>{maskEmail(saved.email)}</span>
					<button class="btn alt sm" type="button" aria-label="Show email address" onclick={() => (showEmail = true)}><Icon name="eye" />Show</button>
				</div>
			{/if}
			<p class="hint">An email set here counts as confirmed. Empty removes it.</p>
		</div>
		<div><label class="lbl" for="pic">Picture address</label><input class="in" id="pic" type="url" bind:value={form.picture_url} placeholder="https://…" /></div>
		<div>
			<label class="lbl" for="lc">Language</label>
			<select class="in" id="lc" bind:value={form.locale}>
				<option value="">Not set</option>
				{#each locales as l (l.tag)}<option value={l.tag}>{l.name} · {l.tag}</option>{/each}
			</select>
		</div>
		<div>
			<label class="lbl" for="tz">Time zone</label>
			<select class="in" id="tz" bind:value={form.zoneinfo}>
				<option value="">Not set</option>
				{#each zones as z (z)}<option value={z}>{z}</option>{/each}
			</select>
		</div>
	</div>
	{@render message('profile')}
	<div class="actions">
		<button class="btn alt" type="button" disabled={!dirty} onclick={() => (form = { ...saved })}>Discard changes</button>
		<button class="btn" type="submit" disabled={!dirty}>Save profile</button>
	</div>
</form>

<section class="card">
	<h2 class="sec-h">Access</h2>
	{@render message('access')}
	<div class="rows">
		<div class="row">
			<span><strong>Sign out everywhere</strong><span class="hint block">Ends all of {name}'s sessions and app tokens.</span></span>
			<button class="btn alt" type="button" onclick={signOutEverywhere}>Sign out everywhere</button>
		</div>
		<form class="row stack" onsubmit={setPassword} novalidate>
			<span><strong>Set a temporary password</strong><span class="hint block">{name} must choose a new one at the next sign-in. At least 10 characters.</span></span>
			<div class="grid2 wide">
				<PasswordField id="tp" label="Temporary password" bind:value={tempPassword} bind:show={showTemp} />
				<PasswordField id="tp2" label="Temporary password again" bind:value={tempPassword2} />
			</div>
			<div class="end wide gen">
				{#if generated}<span class="hint" role="status">{generated}</span>{/if}
				<button class="btn alt" type="button" onclick={generate}>Generate</button>
				<button class="btn" type="submit">Set password</button>
			</div>
		</form>
		{#if account.mfa.totp || (account.mfa.security_keys ?? []).length}
			<form class="row bottom" onsubmit={resetTwoFactor} novalidate>
				<span class="grow">
					<strong>Reset two-factor</strong>
					<span class="hint block">Removes {twoFactorMethods(account.mfa)} and the recovery codes. {name} is emailed. A reason is required.</span>
					<label class="visually-hidden" for="reason">Reason</label>
					<input class="in reason" id="reason" bind:value={reason} maxlength="500" placeholder="Reason, for example: lost their phone" />
				</span>
				<button class="btn alt" type="submit">Reset two-factor</button>
			</form>
		{/if}
		<div class="row">
			{#if account.status === 'active'}
				<span><strong>Disable the account</strong><span class="hint block">Disabling signs {name} out everywhere. You can enable it again.</span></span>
				<button class="btn danger" type="button" onclick={() => setStatus('disabled')}>Disable</button>
			{:else}
				<span><strong>Enable the account</strong><span class="hint block">{name} can sign in again.</span></span>
				<button class="btn" type="button" onclick={() => setStatus('active')}>Enable</button>
			{/if}
		</div>
	</div>
</section>

<section class="card">
	<h2 class="sec-h">Groups</h2>
	{@render message('groups')}
	{#if account.groups.length}
		<div class="scroll list">
			<table class="tbl">
				<thead><tr><th>Group</th><th>Expires</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
				<tbody>
					{#each account.groups as g (g.group_id)}
						<tr>
							<td><a href="/admin/groups/{g.group_id}">{g.display_name}</a>{#if groupBound(g.group_id)}<span class="badge hl small">single-app</span>{/if}</td>
							<td>
								{#if editing === g.group_id}
									<span class="edit">
										<label class="visually-hidden" for="exp-{g.group_id}">Expires</label>
										<input class="in small" id="exp-{g.group_id}" type="date" min={today} bind:value={editDate} />
										<button class="btn sm" type="button" onclick={() => saveExpiry(g.group_id)}>Save</button>
										<button class="btn alt sm" type="button" onclick={() => (editing = null)}>Cancel</button>
									</span>
								{:else}
									{g.expires_at ? formatDate(g.expires_at) : 'Never'}
								{/if}
							</td>
							<td class="end-cell">
								{#if editing !== g.group_id}
									<button class="btn alt sm" type="button" onclick={() => ((editing = g.group_id), (editDate = dateInput(g.expires_at)))}>Change expiry</button>
									<button class="btn alt sm" type="button" onclick={() => removeFromGroup(g.group_id, g.display_name)}>Remove</button>
								{/if}
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="hint none">In no groups.</p>
	{/if}
	<form class="filters add" onsubmit={addToGroup} novalidate>
		<div class="grow2">
			<label class="lbl" for="ag">Add to a group</label>
			<select class="in" id="ag" bind:value={addGroup}>
				<option value="">Choose a group</option>
				{#each addable as g (g.id)}<option value={g.id}>{g.display_name}</option>{/each}
			</select>
		</div>
		<div class="grow1"><label class="lbl" for="ae">Expires</label><input class="in" id="ae" type="date" min={today} bind:value={addExpires} /></div>
		<button class="btn alt" type="submit">Add</button>
	</form>
</section>

<section class="card">
	<h2 class="sec-h">Recent activity</h2>
	{#if data.activity.length}
		<div class="scroll list">
			<table class="tbl">
				<thead><tr><th>When</th><th>Event</th><th>Who</th></tr></thead>
				<tbody>
					{#each data.activity as e (e.id)}
						<tr><td>{formatWhen(e.occurred_at)}</td><td>{eventWords(e.event_type, e.metadata)}</td><td>{e.actor_username || (e.actor_account_id ? 'An erased account' : 'Guardian')}</td></tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="hint none">Nothing yet.</p>
	{/if}
	<p class="more"><a href="/admin/audit?about={account.id}">Open in the audit log</a></p>
</section>

<section class="card danger-card">
	<h2 class="sec-h">Delete</h2>
	{@render message('delete')}
	<div class="rows">
		<div class="row">
			<span><strong>Delete {name}</strong><span class="hint block">Signs them out everywhere. Erased after 30 days; you can restore it until then.</span></span>
			<button class="btn danger" type="button" onclick={remove}>Delete</button>
		</div>
		<div class="row">
			<span><strong>Erase now</strong><span class="hint block">Skips the 30 days. This cannot be undone.</span></span>
			<button class="btn danger" type="button" onclick={erase}>Erase now</button>
		</div>
	</div>
</section>

<style>
	.gen {
		gap: 12px;
		align-items: center;
		flex-wrap: wrap;
	}
	.gen .hint {
		margin: 0 auto 0 0;
	}
	.title {
		display: flex;
		align-items: center;
		gap: 16px;
		flex-wrap: wrap;
	}
	.av {
		border-radius: 50%;
		background: var(--tile);
		display: grid;
		place-items: center;
		font-weight: 600;
		color: var(--accent);
		flex: none;
	}
	.av.big {
		width: 52px;
		height: 52px;
		font-size: 22px;
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
	.badge.hl {
		color: var(--hl);
	}
	.badge.mute {
		color: var(--mute);
	}
	.badge.small {
		font-size: 12px;
		padding: 0 8px;
		margin-left: 8px;
	}
	.meta {
		font-size: 14px;
	}
	.fields,
	.rows,
	.list {
		margin-top: 14px;
	}
	.mask {
		display: flex;
		align-items: center;
		gap: 10px;
		height: 42px;
		padding: 0 6px 0 12px;
		border: 1px solid var(--line);
		border-radius: 6px;
		background: var(--field);
		box-sizing: border-box;
	}
	.mask span {
		flex: 1;
	}
	.msg {
		margin: 14px 0 0;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
		margin-top: 20px;
	}
	.block {
		display: block;
		margin: 0;
	}
	.row.stack {
		align-items: flex-start;
	}
	.row.stack > span,
	.wide {
		flex: 1 1 100%;
	}
	.row.bottom {
		align-items: flex-end;
	}
	.grow {
		flex: 1 1 320px;
	}
	.reason {
		margin-top: 10px;
	}
	.end {
		display: flex;
		justify-content: flex-end;
	}
	.end-cell {
		text-align: right;
		white-space: nowrap;
	}
	.edit {
		display: flex;
		gap: 6px;
		align-items: center;
		flex-wrap: wrap;
	}
	.in.small {
		height: 30px;
		width: auto;
	}
	.none {
		margin: 14px 0 0;
	}
	.filters {
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
		align-items: flex-end;
	}
	.add {
		margin-top: 16px;
	}
	.grow2 {
		flex: 2 1 220px;
	}
	.grow1 {
		flex: 1 1 150px;
	}
	.more {
		margin: 14px 0 0;
	}
	.danger-card {
		border-color: var(--danger);
	}
</style>
