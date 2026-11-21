<!-- AC5 Groups: the groups the user is in, the groups they manage as an owner (each opens AC6, with its
     waiting requests), the groups they may ask to join, and their own requests (A33). Display names only:
     users never need group keys. -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api } from '#lib/api/client.ts';
	import { formatDate, formatWhen, messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const memberOf = $derived(data.groups.member_of);
	const manages = $derived(data.groups.manages);
	const requestable = $derived(data.requests.requestable.filter((g) => !g.requested));
	const myRequests = $derived(data.requests.requests);

	let messages = $state<Record<string, string>>({});
	let busy = $state('');
	let note = $state<{ ok: boolean; text: string } | null>(null);
	const decisionWords: Record<string, string> = { approved: 'Approved', denied: 'Denied', withdrawn: 'Withdrawn' };

	async function ask(id: string, name: string) {
		busy = id;
		note = null;
		try {
			await api.post('/me/group-requests', { body: { group_id: id, ...(messages[id]?.trim() ? { message: messages[id].trim() } : {}) } });
			note = { ok: true, text: `You asked to join ${name}. You get an email when it is decided.` };
			messages[id] = '';
			await refreshAll();
		} catch (e) {
			note = { ok: false, text: messageOf(e) };
		} finally {
			busy = '';
		}
	}

	async function withdraw(id: string) {
		busy = id;
		note = null;
		try {
			await api.delete('/me/group-requests/{request}', { path: { request: id } });
			await refreshAll();
		} catch (e) {
			note = { ok: false, text: messageOf(e) };
		} finally {
			busy = '';
		}
	}
</script>

<svelte:head><title>Groups · Guardian</title></svelte:head>

<div class="ph"><h1>Groups</h1><p>Groups decide which apps you can use and what you can do in them.</p></div>

{#if !memberOf.length && !manages.length}
	<section class="card">
		<p class="empty">You are not in any groups yet. {requestable.length ? 'Ask to join one below, or' : 'An administrator or group owner can'} add you.</p>
	</section>
{:else}
	{#if memberOf.length}
		<section class="card">
			<h2 class="sec-h">Groups you're in</h2>
			<div class="scroll">
				<table class="tbl">
					<thead><tr><th>Group</th><th>Description</th><th>Expires</th></tr></thead>
					<tbody>
						{#each memberOf as g (g.id)}
							<tr><td><strong>{g.display_name}</strong></td><td>{g.description}</td><td>{g.expires_at ? formatDate(g.expires_at) : 'Never'}</td></tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}

	{#if manages.length}
		<section class="card">
			<h2 class="sec-h">Groups you manage</h2>
			<p class="hint intro">You can add and remove members of these.</p>
			<div class="scroll">
				<table class="tbl">
					<thead><tr><th>Group</th><th class="num">Members</th><th>Linked apps</th><th><span class="visually-hidden">Open</span></th></tr></thead>
					<tbody>
						{#each manages as g (g.id)}
							<tr>
								<td><strong>{g.display_name}</strong>{#if g.open_requests}<span class="badge hl req">{g.open_requests === 1 ? '1 request' : `${g.open_requests} requests`}</span>{/if}</td>
								<td class="num">{g.member_count}</td>
								<td>{g.apps.length ? g.apps.join(', ') : 'None'}</td>
								<td class="end"><a class="btn alt sm" href="/account/groups/{g.id}" aria-label="Open {g.display_name}">Open</a></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}
{/if}

{#if note}<p class={note.ok ? 'ok-msg msg' : 'err-msg msg'} role={note.ok ? 'status' : 'alert'}>{note.text}</p>{/if}

{#if myRequests.length}
	<section class="card">
		<h2 class="sec-h">Your requests</h2>
		<div class="rows">
			{#each myRequests as q (q.id)}
				<div class="row">
					<span class="grow"><strong>{q.group_name}</strong><span class="hint block">Asked {formatWhen(q.created_at)}{q.decided_at ? ` · ${decisionWords[q.decision ?? ''] ?? ''} ${formatWhen(q.decided_at)}` : ''}</span></span>
					{#if q.decision}
						<span class="badge {q.decision === 'approved' ? 'ok' : 'mute'}">{decisionWords[q.decision]}</span>
					{:else}
						<span class="badge hl">Waiting</span>
						<button class="btn alt sm" type="button" disabled={busy === q.id} onclick={() => withdraw(q.id)}>Withdraw</button>
					{/if}
				</div>
			{/each}
		</div>
	</section>
{/if}

{#if requestable.length}
	<section class="card">
		<h2 class="sec-h">Ask to join</h2>
		<p class="hint intro">Groups you can ask to join. Their owners decide, and you get an email.</p>
		<div class="rows">
			{#each requestable as g (g.id)}
				<div class="row">
					<span class="grow"><strong>{g.display_name}</strong>{#if g.description}<span class="hint block">{g.description}</span>{/if}</span>
					<span class="ask">
						<label class="visually-hidden" for="msg-{g.id}">Message to {g.display_name}'s owners (optional)</label>
						<input class="in" id="msg-{g.id}" maxlength="500" placeholder="Why you need it (optional)" bind:value={messages[g.id]} />
						<button class="btn" type="button" disabled={busy === g.id} onclick={() => ask(g.id, g.display_name)}>Ask to join</button>
					</span>
				</div>
			{/each}
		</div>
	</section>
{/if}

<style>
	.rows {
		display: flex;
		flex-direction: column;
	}
	.row {
		display: flex;
		gap: 14px;
		align-items: center;
		padding: 12px 0;
		border-top: 1px solid var(--line);
		flex-wrap: wrap;
	}
	.row:first-child {
		border-top: 0;
	}
	.grow {
		flex: 1 1 220px;
		min-width: 0;
	}
	.block {
		display: block;
	}
	.ask {
		display: flex;
		gap: 10px;
		flex: 1 1 320px;
	}
	.ask .in {
		flex: 1;
		min-width: 0;
	}
	.req {
		margin-left: 8px;
	}
	.msg {
		margin: 0 0 16px;
	}
	.scroll {
		margin-top: 14px;
	}
	.intro {
		margin: 0 0 4px;
	}
	td strong {
		font-weight: 600;
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
