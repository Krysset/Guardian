<!-- AD1 Accounts: search, filter by status, page through; open one (AD2) or create one (AD3). Email addresses
     are masked: they show in full on the account's own page. -->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import Icon from '#lib/components/Icon.svelte';
	import { formatWhen, maskEmail } from '#lib/format.ts';
	import { _pageSize as pageSize } from './+page.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	// svelte-ignore state_referenced_locally
	let q = $state(data.q);
	// The cursors of the pages before this one, for Previous. Kept while the search and filter stay the same.
	let previous = $state<string[]>([]);
	let timer: ReturnType<typeof setTimeout> | undefined;

	const accounts = $derived(data.page.items);
	const total = $derived(data.page.total);
	const first = $derived(previous.length * pageSize + 1);

	// Moves to another page of the list; `after` runs once it has loaded, so the numbers never show the new
	// position with the old rows.
	async function go(params: { q?: string; status?: string; cursor?: string }, after?: () => void) {
		const url = new URL(page.url.href);
		for (const [k, v] of Object.entries(params)) {
			if (v) url.searchParams.set(k, v);
			else url.searchParams.delete(k);
		}
		await goto(url, { replace: true, reset: false });
		after?.();
	}

	function search() {
		clearTimeout(timer);
		timer = setTimeout(() => go({ q: q.trim(), cursor: '' }, () => (previous = [])), 250);
	}

	function filter(event: Event) {
		go({ status: (event.currentTarget as HTMLSelectElement).value, cursor: '' }, () => (previous = []));
	}

	function next() {
		if (!data.page.next_cursor) return;
		const here = data.cursor;
		go({ cursor: data.page.next_cursor }, () => (previous = [...previous, here]));
	}

	function back() {
		go({ cursor: previous.at(-1) ?? '' }, () => (previous = previous.slice(0, -1)));
	}

	const statusBadge = (a: (typeof accounts)[number]) =>
		a.status === 'active' ? (a.must_change_password ? { text: 'Must change password', cls: 'hl' } : { text: 'Active', cls: 'ok' }) : { text: a.status === 'disabled' ? 'Disabled' : a.status, cls: 'mute' };
</script>

<svelte:head><title>Accounts · Guardian</title></svelte:head>

<div class="head">
	<div class="ph"><h1>Accounts</h1><p>{total === 1 ? '1 account' : `${total} accounts`}{data.q || data.status ? ' found' : ''}</p></div>
	<a class="btn" href="/admin/accounts/new"><Icon name="plus" />New account</a>
</div>

<section class="card">
	<div class="filters">
		<div class="search">
			<label class="lbl" for="q">Search</label>
			<input class="in" id="q" type="search" bind:value={q} oninput={search} placeholder="Username, name or email" autocomplete="off" />
		</div>
		<div class="status">
			<label class="lbl" for="sf">Status</label>
			<select class="in" id="sf" value={data.status} onchange={filter}>
				<option value="">All</option>
				<option value="active">Active</option>
				<option value="disabled">Disabled</option>
				<option value="must_change_password">Must change password</option>
			</select>
		</div>
	</div>

	{#if accounts.length}
		<div class="scroll list">
			<table class="tbl">
				<thead><tr><th>Username</th><th>Display name</th><th>Email</th><th>Status</th><th>Last sign-in</th></tr></thead>
				<tbody>
					{#each accounts as a (a.id)}
						{@const badge = statusBadge(a)}
						<tr>
							<td><a href="/admin/accounts/{a.id}">{a.username}</a></td>
							<td>{a.display_name ?? ''}</td>
							<td>{a.email ? maskEmail(a.email) : '—'}</td>
							<td><span class="badge {badge.cls}">{badge.text}</span></td>
							<td>{a.last_login_at ? formatWhen(a.last_login_at) : 'Never'}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<div class="pager">
			<span>{first}–{first + accounts.length - 1} of {total}</span>
			<span class="buttons">
				<button class="btn alt sm" type="button" disabled={!previous.length} onclick={back}>Previous</button>
				<button class="btn alt sm" type="button" disabled={!data.page.next_cursor} onclick={next}>Next</button>
			</span>
		</div>
	{:else}
		<p class="empty">{data.q || data.status ? 'No accounts match.' : 'No accounts yet.'}</p>
	{/if}
</section>

<style>
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-end;
		gap: 16px;
		flex-wrap: wrap;
	}
	.filters {
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
		align-items: flex-end;
	}
	.search {
		flex: 3 1 280px;
	}
	.status {
		flex: 1 1 160px;
	}
	.list {
		margin-top: 18px;
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
	.pager {
		display: flex;
		justify-content: space-between;
		align-items: center;
		margin-top: 14px;
		font-size: 14px;
		color: var(--mute);
	}
	.buttons {
		display: flex;
		gap: 8px;
	}
	.empty {
		margin: 18px 0 0;
		padding: 24px;
		text-align: center;
		border: 1px dashed var(--line);
		border-radius: 8px;
		color: var(--mute);
	}
</style>
