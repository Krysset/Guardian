<!-- AC6 Owned group: an owner adds members by exact username or email (no suggestions, so the only answers
     are "No user found" and "User added"), changes when a membership expires, and removes members. The linked
     apps are shown by name; only an administrator can change them. -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import Icon from '#lib/components/Icon.svelte';
	import { dateInput, endOfDay, formatDate, initial, messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const group = $derived(data.group);
	const members = $derived(data.members);
	const today = dateInput(new Date().toISOString());

	let login = $state('');
	let expires = $state('');
	let addResult = $state<{ ok: boolean; text: string } | null>(null);
	let busy = $state(false);
	let error = $state('');
	let editing = $state<string | null>(null);
	let editDate = $state('');

	async function add(event: SubmitEvent) {
		event.preventDefault();
		addResult = null;
		error = '';
		if (!login.trim()) {
			addResult = { ok: false, text: 'Type a username or an email address.' };
			return;
		}
		busy = true;
		try {
			const r = await api.post('/groups/{group}/members', {
				path: { group: group.id },
				body: { login: login.trim(), ...(expires ? { expires_at: endOfDay(expires) } : {}) }
			});
			addResult = { ok: true, text: `User added: ${r.username}` };
			login = '';
			expires = '';
			await refreshAll();
		} catch (e) {
			addResult = { ok: false, text: e instanceof ApiError && e.status === 404 ? 'No user found' : messageOf(e) };
		} finally {
			busy = false;
		}
	}

	function startEdit(accountId: string, current?: string) {
		editing = accountId;
		editDate = dateInput(current);
	}

	async function saveExpiry(accountId: string) {
		error = '';
		try {
			await api.put('/groups/{group}/members/{account}', {
				path: { group: group.id, account: accountId },
				body: editDate ? { expires_at: endOfDay(editDate) } : {}
			});
			editing = null;
			await refreshAll();
		} catch (e) {
			error = messageOf(e);
		}
	}

	async function remove(accountId: string, name: string) {
		error = '';
		const ok = await askConfirm({
			title: `Remove ${name} from ${group.display_name}?`,
			message: 'They lose what this group gives them in its apps at once.',
			confirm: 'Remove',
			danger: true
		});
		if (!ok) return;
		try {
			await api.delete('/groups/{group}/members/{account}', { path: { group: group.id, account: accountId } });
			await refreshAll();
		} catch (e) {
			error = messageOf(e);
		}
	}
</script>

<svelte:head><title>{group.display_name} · Guardian</title></svelte:head>

<div class="ph">
	<p class="crumb"><a href="/account/groups">Groups</a> / {group.display_name}</p>
	<h1>{group.display_name}</h1>
	{#if group.description}<p>{group.description}</p>{/if}
</div>

<section class="card">
	<h2 class="sec-h">Linked apps</h2>
	<p class="hint intro">Members can sign in to these apps. Only an administrator can change them.</p>
	{#if group.apps.length}
		<div class="chips">{#each group.apps as name (name)}<span class="chip">{name}</span>{/each}</div>
	{:else}
		<p class="hint none">None yet.</p>
	{/if}
</section>

<form class="card" onsubmit={add} novalidate>
	<h2 class="sec-h">Add a member</h2>
	<p class="hint intro">Leave the expiry empty to keep them until you remove them.</p>
	<div class="filters">
		<div class="who">
			<label class="lbl" for="who">Username or email</label>
			<input class="in" id="who" bind:value={login} placeholder="Exact username or email" autocomplete="off" autocapitalize="none" spellcheck="false" />
		</div>
		<div class="when">
			<label class="lbl" for="exp">Expires</label>
			<input class="in" id="exp" type="date" min={today} bind:value={expires} />
		</div>
		<button class="btn" type="submit" disabled={busy}><Icon name="plus" />Add</button>
	</div>
	<p class="hint">Type it exactly. There are no suggestions.</p>
	{#if addResult}
		<p class={addResult.ok ? 'ok-msg result' : 'err-msg result'} role={addResult.ok ? 'status' : 'alert'}>{addResult.text}</p>
	{/if}
</form>

<section class="card">
	<h2 class="sec-h">Members</h2>
	<p class="hint intro">{members.length === 1 ? '1 member' : `${members.length} members`}</p>
	{#if error}<p class="err-msg result" role="alert">{error}</p>{/if}
	{#if members.length}
		<div class="scroll">
			<table class="tbl">
				<thead><tr><th>Member</th><th>Added</th><th>Expires</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
				<tbody>
					{#each members as m (m.account_id)}
						<tr>
							<td>
								<span class="member">
									<span class="av" aria-hidden="true">{initial(m.display_name || m.username)}</span>
									<span><strong>{m.display_name || m.username}</strong><span class="hint block">{m.username}</span></span>
								</span>
							</td>
							<td>{formatDate(m.added_at)}</td>
							<td>
								{#if editing === m.account_id}
									<span class="edit">
										<label class="visually-hidden" for="exp-{m.account_id}">Expires for {m.username}</label>
										<input class="in small" id="exp-{m.account_id}" type="date" min={today} bind:value={editDate} />
										<button class="btn sm" type="button" onclick={() => saveExpiry(m.account_id)}>Save</button>
										<button class="btn alt sm" type="button" onclick={() => (editing = null)}>Cancel</button>
									</span>
									<span class="hint block">Empty: never.</span>
								{:else}
									{m.expires_at ? formatDate(m.expires_at) : 'Never'}
									<button class="btn alt sm change" type="button" aria-label="Change expiry for {m.username}" onclick={() => startEdit(m.account_id, m.expires_at)}>Change</button>
								{/if}
							</td>
							<td class="end"><button class="btn alt sm" type="button" onclick={() => remove(m.account_id, m.display_name || m.username)}>Remove</button></td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="empty">No members yet. Add someone above.</p>
	{/if}
</section>

<style>
	.intro {
		margin: 0 0 18px;
	}
	.none {
		margin: 0;
	}
	.chips {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}
	.chip {
		display: inline-flex;
		padding: 4px 12px;
		border: 1px solid var(--line);
		border-radius: 99px;
		background: var(--bg);
		font-size: 14px;
	}
	.filters {
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
		align-items: flex-end;
	}
	.who {
		flex: 2 1 260px;
	}
	.when {
		flex: 1 1 160px;
	}
	.result {
		margin: 14px 0 0;
	}
	.member {
		display: flex;
		gap: 10px;
		align-items: center;
	}
	.member strong {
		font-weight: 600;
	}
	.av {
		width: 36px;
		height: 36px;
		border-radius: 50%;
		background: var(--tile);
		display: grid;
		place-items: center;
		font-weight: 600;
		color: var(--accent);
		flex: none;
	}
	.block {
		display: block;
		margin: 0;
	}
	.change {
		margin-left: 6px;
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
	.end {
		text-align: right;
	}
	.empty {
		margin: 0;
		padding: 24px;
		text-align: center;
		border: 1px dashed var(--line);
		border-radius: 8px;
		color: var(--mute);
	}
</style>
