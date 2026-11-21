<!-- Open requests to join a group (A33), for its owners (AC6) and administrators (AD5): approve, optionally
     until a date, or deny. The requester gets an email either way. -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, type Schema } from '#lib/api/client.ts';
	import { endOfDay, formatWhen, messageOf } from '#lib/format.ts';

	let { groupId, groupName, requests }: { groupId: string; groupName: string; requests: Schema<'GroupRequest'>[] } = $props();

	let until = $state<Record<string, string>>({});
	let busy = $state('');
	let note = $state<{ ok: boolean; text: string } | null>(null);
	const today = new Date().toISOString().slice(0, 10);

	async function decide(q: Schema<'GroupRequest'>, approve: boolean) {
		busy = q.id;
		note = null;
		try {
			const date = until[q.id];
			await api.post('/groups/{group}/requests/{request}', {
				path: { group: groupId, request: q.id },
				body: { approve, ...(approve && date ? { expires_at: endOfDay(date) } : {}) }
			});
			const who = q.display_name || q.username;
			note = { ok: true, text: approve ? `${who} was added to ${groupName}.` : `${who}'s request was denied.` };
			await refreshAll();
		} catch (e) {
			note = { ok: false, text: messageOf(e) };
		} finally {
			busy = '';
		}
	}
</script>

{#if requests.length || note}
	<section class="card">
		<h2 class="sec-h">Requests to join</h2>
		<p class="hint intro">They are emailed when you decide.</p>
		{#if note}<p class={note.ok ? 'ok-msg msg' : 'err-msg msg'} role={note.ok ? 'status' : 'alert'}>{note.text}</p>{/if}
		<div class="rows">
			{#each requests as q (q.id)}
				<div class="row">
					<span class="grow">
						<strong>{q.display_name || q.username}</strong>{#if q.display_name}<span class="hint"> {q.username}</span>{/if}
						<span class="hint block">Asked {formatWhen(q.created_at)}</span>
						{#if q.message}<span class="message">“{q.message}”</span>{/if}
					</span>
					<span class="decide">
						<label class="lbl small" for="until-{q.id}">Until (optional)</label>
						<input class="in" id="until-{q.id}" type="date" min={today} bind:value={until[q.id]} />
						<span class="buttons">
							<button class="btn alt" type="button" disabled={busy === q.id} onclick={() => decide(q, false)}>Deny</button>
							<button class="btn" type="button" disabled={busy === q.id} onclick={() => decide(q, true)}>Approve</button>
						</span>
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
		gap: 18px;
		align-items: flex-end;
		justify-content: space-between;
		padding: 14px 0;
		border-top: 1px solid var(--line);
		flex-wrap: wrap;
	}
	.row:first-child {
		border-top: 0;
	}
	.grow {
		flex: 1 1 260px;
		min-width: 0;
	}
	.block {
		display: block;
	}
	.message {
		display: block;
		margin-top: 6px;
		overflow-wrap: anywhere;
	}
	.decide {
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.small {
		font-size: 13px;
	}
	.buttons {
		display: flex;
		gap: 10px;
		margin-top: 4px;
	}
	.msg {
		margin: 0 0 12px;
	}
</style>
