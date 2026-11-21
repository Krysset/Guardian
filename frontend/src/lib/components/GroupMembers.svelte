<!-- A group's members (AC6 for owners, AD5 for administrators): add one, change when a membership expires,
     remove one. Owners type an exact username or email and get only "No user found" or "User added";
     administrators may also search accounts (`search`). -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, ApiError, type Schema } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import { dateInput, endOfDay, formatDate, initial, messageOf } from '#lib/format.ts';
	import Icon from './Icon.svelte';

	let {
		groupId,
		groupName,
		members,
		search = false,
		accountLinks = false
	}: { groupId: string; groupName: string; members: Schema<'GroupMember'>[]; search?: boolean; accountLinks?: boolean } = $props();

	const today = dateInput(new Date().toISOString());
	let login = $state('');
	let expires = $state('');
	let addResult = $state<{ ok: boolean; text: string } | null>(null);
	let busy = $state(false);
	let error = $state('');
	let editing = $state<string | null>(null);
	let editDate = $state('');
	let matches = $state<Schema<'Account'>[]>([]);
	let timer: ReturnType<typeof setTimeout> | undefined;

	const memberIds = $derived(new Set(members.map((m) => m.account_id)));
	const expiresAt = () => (expires ? { expires_at: endOfDay(expires) } : {});

	function lookup() {
		if (!search) return;
		clearTimeout(timer);
		const q = login.trim();
		if (q.length < 2) {
			matches = [];
			return;
		}
		timer = setTimeout(async () => {
			try {
				const page = await api.get('/accounts', { query: { q, limit: 6 } });
				matches = page.items.filter((a) => !memberIds.has(a.id));
			} catch {
				matches = [];
			}
		}, 200);
	}

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
			const r = await api.post('/groups/{group}/members', { path: { group: groupId }, body: { login: login.trim(), ...expiresAt() } });
			done(r.username ?? login.trim());
		} catch (e) {
			addResult = { ok: false, text: e instanceof ApiError && e.status === 404 ? 'No user found' : messageOf(e) };
		} finally {
			busy = false;
		}
	}

	async function addAccount(account: Schema<'Account'>) {
		addResult = null;
		try {
			await api.put('/groups/{group}/members/{account}', { path: { group: groupId, account: account.id }, body: expiresAt() });
			done(account.username);
		} catch (e) {
			addResult = { ok: false, text: messageOf(e) };
		}
	}

	async function done(username: string) {
		addResult = { ok: true, text: `User added: ${username}` };
		login = '';
		expires = '';
		matches = [];
		await refreshAll();
	}

	async function saveExpiry(accountId: string) {
		error = '';
		try {
			await api.put('/groups/{group}/members/{account}', { path: { group: groupId, account: accountId }, body: editDate ? { expires_at: endOfDay(editDate) } : {} });
			editing = null;
			await refreshAll();
		} catch (e) {
			error = messageOf(e);
		}
	}

	async function remove(accountId: string, name: string) {
		error = '';
		if (!(await askConfirm({ title: `Remove ${name} from ${groupName}?`, message: 'They lose what this group gives them in its apps at once.', confirm: 'Remove', danger: true }))) return;
		try {
			await api.delete('/groups/{group}/members/{account}', { path: { group: groupId, account: accountId } });
			await refreshAll();
		} catch (e) {
			error = e instanceof ApiError && e.code === 'last_admin' ? 'This is the last administrator whose membership does not expire.' : messageOf(e);
		}
	}
</script>

<form class="card" onsubmit={add} novalidate>
	<h2 class="sec-h">Add a member</h2>
	<p class="hint intro">Leave the expiry empty to keep them until they are removed.</p>
	<div class="filters">
		<div class="who">
			<label class="lbl" for="who">Username or email</label>
			<input class="in" id="who" bind:value={login} oninput={lookup} placeholder={search ? 'Search accounts' : 'Exact username or email'} autocomplete="off" autocapitalize="none" spellcheck="false" />
		</div>
		<div class="when">
			<label class="lbl" for="exp">Expires</label>
			<input class="in" id="exp" type="date" min={today} bind:value={expires} />
		</div>
		<button class="btn" type="submit" disabled={busy}><Icon name="plus" />Add</button>
	</div>
	{#if search && matches.length}
		<ul class="matches" aria-label="Matching accounts">
			{#each matches as a (a.id)}
				<li>
					<span><strong>{a.display_name || a.username}</strong> <span class="hint inline">{a.username}</span></span>
					<button class="btn alt sm" type="button" aria-label="Add {a.username}" onclick={() => addAccount(a)}>Add</button>
				</li>
			{/each}
		</ul>
	{:else if !search}
		<p class="hint">Type it exactly. There are no suggestions.</p>
	{/if}
	{#if addResult}<p class={addResult.ok ? 'ok-msg result' : 'err-msg result'} role={addResult.ok ? 'status' : 'alert'}>{addResult.text}</p>{/if}
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
									<span>
										{#if accountLinks}<a href="/admin/accounts/{m.account_id}">{m.display_name || m.username}</a>{:else}<strong>{m.display_name || m.username}</strong>{/if}
										<span class="hint block">{m.username}</span>
									</span>
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
									<button class="btn alt sm change" type="button" aria-label="Change expiry for {m.username}" onclick={() => ((editing = m.account_id), (editDate = dateInput(m.expires_at)))}>Change</button>
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
	.matches {
		list-style: none;
		margin: 10px 0 0;
		padding: 6px;
		border: 1px solid var(--line);
		border-radius: 8px;
		background: var(--field);
	}
	.matches li {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		padding: 6px 8px;
	}
	.matches strong {
		font-weight: 600;
	}
	.inline {
		margin: 0 0 0 6px;
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
