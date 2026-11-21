<!-- AD11 Audit log: every entry, newest first, filtered by event and by account (an exact username: what it
     did and what was done to it), or by app from an app's page. A row opens to show all its details. -->
<script lang="ts">
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import type { Schema } from '#lib/api/client.ts';
	import { eventGroups, eventWords, summary, who } from '#lib/events.ts';
	import { formatDays, formatWhen } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	// svelte-ignore state_referenced_locally
	let username = $state(data.username);
	let open = $state<number | null>(null);
	// The cursors of the pages before this one, for Previous. Kept while the filters stay the same.
	let previous = $state<string[]>([]);

	const entries = $derived(data.page.items);
	const filtered = $derived(Boolean(data.event || data.username || data.app));

	async function go(params: Record<string, string>, after?: () => void) {
		const url = new URL(page.url.href);
		for (const [k, v] of Object.entries(params)) {
			if (v) url.searchParams.set(k, v);
			else url.searchParams.delete(k);
		}
		open = null;
		await goto(url, { replace: true, reset: false });
		after?.();
	}
	const refilter = (params: Record<string, string>) => go({ ...params, cursor: '' }, () => (previous = []));

	function byUser(event: SubmitEvent) {
		event.preventDefault();
		refilter({ username: username.trim() });
	}

	function clear() {
		username = '';
		refilter({ event: '', username: '', app: '' });
	}

	function next() {
		if (!data.page.next_cursor) return;
		const here = data.cursor;
		go({ cursor: data.page.next_cursor }, () => (previous = [...previous, here]));
	}

	function back() {
		go({ cursor: previous.at(-1) ?? '' }, () => (previous = previous.slice(0, -1)));
	}

	const idOf = (v: unknown) => (typeof v === 'string' && /^[0-9a-f-]{36}$/.test(v) ? v : '');
	function links(e: Schema<'AuditEntry'>) {
		const m = (e.metadata ?? {}) as Record<string, unknown>;
		const out: { label: string; text: string; href?: string }[] = [];
		if (e.actor_account_id) out.push({ label: 'Done by', text: e.actor_username || 'An erased account', href: e.actor_username ? `/admin/accounts/${e.actor_account_id}` : undefined });
		const target = idOf(m.target) || idOf(m.account);
		if (target && target !== e.actor_account_id) out.push({ label: 'Account', text: e.target_username || 'An erased account', href: e.target_username ? `/admin/accounts/${target}` : undefined });
		const app = e.actor_app_id || idOf(m.app);
		if (app) out.push({ label: 'App', text: e.app_name || (typeof m.name === 'string' ? `${m.name} (deleted)` : 'A deleted app'), href: e.app_name ? `/admin/apps/${app}` : undefined });
		const group = idOf(m.group);
		if (group) out.push({ label: 'Group', text: e.group_name || (typeof m.key === 'string' ? `${m.key} (deleted)` : 'A deleted group'), href: e.group_name ? `/admin/groups/${group}` : undefined });
		if (e.ip_address) out.push({ label: 'IP address', text: e.ip_address });
		return out;
	}
</script>

<svelte:head><title>Audit log · Guardian</title></svelte:head>

<div class="ph"><h1>Audit log</h1><p>Everything that happened in Guardian, newest first. Entries are kept for {formatDays(data.overview.audit_retention_days)}.</p></div>

<section class="card">
	<div class="filters">
		<div class="event">
			<label class="lbl" for="ev">Event</label>
			<select class="in" id="ev" value={data.event} onchange={(e) => refilter({ event: e.currentTarget.value })}>
				<option value="">All events</option>
				{#each eventGroups as g (g.label)}
					<optgroup label={g.label}>
						{#each g.types as t (t)}<option value={t}>{eventWords(t)}</option>{/each}
					</optgroup>
				{/each}
			</select>
		</div>
		<form class="user" onsubmit={byUser}>
			<label class="lbl" for="un">Account</label>
			<div class="row">
				<input class="in" id="un" type="search" bind:value={username} placeholder="Exact username" autocomplete="off" autocapitalize="none" spellcheck="false" aria-describedby="un-hint" />
				<button class="btn alt" type="submit">Show</button>
			</div>
		</form>
	</div>
	<p class="hint" id="un-hint">An account shows what it did and what was done to it.</p>
	{#if filtered}
		<div class="chips">
			{#if data.app}<span class="badge">App: {data.appName}</span>{/if}
			{#if data.username}<span class="badge">Account: {data.username}</span>{/if}
			{#if data.event}<span class="badge">Event: {eventWords(data.event)}</span>{/if}
			<button class="link" type="button" onclick={clear}>Clear filters</button>
		</div>
	{/if}

	{#if data.unknownUser}
		<p class="empty" role="alert">No account has the username “{data.username}”.</p>
	{:else if entries.length}
		<div class="scroll list">
			<table class="tbl">
				<thead><tr><th>When</th><th>Event</th><th>Who</th><th class="ip">IP address</th><th>About</th><th><span class="visually-hidden">Details</span></th></tr></thead>
				<tbody>
					{#each entries as e (e.id)}
						<tr class:open={open === e.id}>
							<td class="nowrap">{formatWhen(e.occurred_at)}</td>
							<td>{eventWords(e.event_type, e.metadata)}</td>
							<td>{who(e)}</td>
							<td class="ip mono">{e.ip_address ?? ''}</td>
							<td class="about">{summary(e)}</td>
							<td class="end">
								<button class="btn alt sm" type="button" aria-expanded={open === e.id} aria-controls="d{e.id}" onclick={() => (open = open === e.id ? null : e.id)}>
									{open === e.id ? 'Hide' : 'Details'}
								</button>
							</td>
						</tr>
						{#if open === e.id}
							<tr class="detail" id="d{e.id}">
								<td colspan="6">
									<dl>
										<dt>Time</dt><dd>{new Date(e.occurred_at).toLocaleString()} <span class="mute">({e.occurred_at})</span></dd>
										<dt>Event</dt><dd><code>{e.event_type}</code></dd>
										{#each links(e) as l (l.label)}
											<dt>{l.label}</dt><dd>{#if l.href}<a href={l.href}>{l.text}</a>{:else}{l.text}{/if}</dd>
										{/each}
										<dt>Entry</dt><dd><code>{e.id}</code></dd>
									</dl>
									{#if Object.keys(e.metadata ?? {}).length}
										<p class="lbl">Recorded details</p>
										<pre>{JSON.stringify(e.metadata, null, 2)}</pre>
									{/if}
								</td>
							</tr>
						{/if}
					{/each}
				</tbody>
			</table>
		</div>
		<div class="pager">
			<span>{previous.length ? `Page ${previous.length + 1}` : 'Newest'}</span>
			<span class="buttons">
				<button class="btn alt sm" type="button" disabled={!previous.length} onclick={back}>Previous</button>
				<button class="btn alt sm" type="button" disabled={!data.page.next_cursor} onclick={next}>Next</button>
			</span>
		</div>
	{:else}
		<p class="empty">{filtered ? 'No entries match.' : 'Nothing has happened yet.'}</p>
	{/if}
</section>

<style>
	.filters {
		display: flex;
		gap: 12px;
		flex-wrap: wrap;
		align-items: flex-start;
	}
	.filters > * {
		margin: 0;
	}
	.event {
		flex: 1 1 240px;
	}
	.user {
		flex: 2 1 300px;
	}
	.row {
		display: flex;
		gap: 8px;
	}
	.row .in {
		flex: 1;
		min-width: 0;
	}
	#un-hint {
		margin: 8px 0 0;
	}
	.chips {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
		align-items: center;
		margin-top: 14px;
	}
	.link {
		background: none;
		border: 0;
		padding: 0 4px;
		color: var(--accent);
		font: inherit;
		text-decoration: underline;
		cursor: pointer;
	}
	.list {
		margin-top: 18px;
	}
	.nowrap {
		white-space: nowrap;
	}
	.mono,
	code,
	pre {
		font-family: ui-monospace, Menlo, Consolas, monospace;
	}
	.mono {
		font-size: 13px;
	}
	.about {
		color: var(--mute);
	}
	.end {
		text-align: right;
	}
	tr.open td {
		border-bottom-color: transparent;
	}
	.detail td {
		background: var(--sel);
	}
	dl {
		display: grid;
		grid-template-columns: max-content 1fr;
		gap: 6px 18px;
		margin: 4px 0 0;
	}
	dt {
		color: var(--mute);
	}
	dd {
		margin: 0;
		overflow-wrap: anywhere;
	}
	.mute {
		color: var(--mute);
	}
	pre {
		margin: 6px 0 0;
		padding: 12px 14px;
		border: 1px solid var(--line);
		border-radius: 8px;
		font-size: 13px;
		white-space: pre-wrap;
		overflow-wrap: anywhere;
	}
	.pager {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		margin-top: 16px;
		color: var(--mute);
	}
	.buttons {
		display: flex;
		gap: 8px;
	}
	.empty {
		margin: 22px 0 4px;
		color: var(--mute);
	}
	/* On a phone each entry is a small card: when and what on top, who and about below, details under it. */
	@media (max-width: 720px) {
		.list {
			overflow: visible;
		}
		.tbl,
		.tbl tbody {
			display: block;
		}
		.tbl thead {
			display: none;
		}
		.tbl tr {
			display: grid;
			grid-template-columns: 1fr auto;
			column-gap: 12px;
			padding: 12px 0;
			border-bottom: 1px solid var(--line);
		}
		.tbl td {
			display: block;
			padding: 0;
			border: 0;
		}
		.tbl td:nth-child(1) {
			grid-column: 1;
			color: var(--mute);
			font-size: 14px;
		}
		.tbl td:nth-child(2) {
			grid-column: 1;
			font-weight: 600;
		}
		.tbl td:nth-child(3),
		.tbl td.about {
			grid-column: 1;
		}
		.ip {
			display: none !important;
		}
		.tbl td.end {
			grid-column: 2;
			grid-row: 1 / span 4;
			align-self: center;
		}
		.tbl tr.open {
			border-bottom: 0;
		}
		.tbl tr.detail {
			display: block;
			padding: 0 0 12px;
		}
		.tbl tr.detail td {
			padding: 12px 14px;
			border-radius: 8px;
		}
	}
</style>
