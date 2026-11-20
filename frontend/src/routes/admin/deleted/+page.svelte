<!-- AD12 Deleted accounts: accounts in their grace period. Restore one, or erase it now (type the username). -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import { formatDate, messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const deleted = $derived(data.deleted);

	let note = $state<{ ok: boolean; text: string } | null>(null);

	async function restore(id: string, name: string) {
		note = null;
		try {
			await api.post('/accounts/{account}/restore', { path: { account: id } });
			await refreshAll();
			await goto(`/admin/accounts/${id}`);
		} catch (e) {
			note = { ok: false, text: messageOf(e) };
		}
	}

	async function erase(id: string, name: string) {
		note = null;
		const ok = await askConfirm({
			title: `Erase ${name} now?`,
			message: 'The account and what it owns are deleted at once. This cannot be undone.',
			confirm: 'Erase now',
			danger: true,
			typeToConfirm: name
		});
		if (!ok) return;
		try {
			await api.post('/accounts/{account}/erase', { path: { account: id }, body: { username: name } });
			note = { ok: true, text: `${name} is erased.` };
			await refreshAll();
		} catch (e) {
			if (!(e instanceof ApiError && e.code === 'cancelled')) note = { ok: false, text: messageOf(e) };
		}
	}
</script>

<svelte:head><title>Deleted accounts · Guardian</title></svelte:head>

<div class="ph"><h1>Deleted accounts</h1><p>Accounts in their grace period. Restore one, or erase it now.</p></div>

<section class="card">
	{#if note}<p class={note.ok ? 'ok-msg msg' : 'err-msg msg'} role={note.ok ? 'status' : 'alert'}>{note.text}</p>{/if}
	{#if deleted.length}
		<div class="scroll">
			<table class="tbl">
				<thead><tr><th>Username</th><th>Deleted</th><th>Erased on</th><th>Deleted by</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
				<tbody>
					{#each deleted as d (d.id)}
						<tr>
							<td><strong>{d.username}</strong></td>
							<td>{formatDate(d.deleted_at)}</td>
							<td>{formatDate(d.erase_after)}</td>
							<td>{d.deleted_by_itself ? 'Themselves' : d.deleted_by_username || 'An erased account'}</td>
							<td class="end">
								<button class="btn alt sm" type="button" onclick={() => restore(d.id ?? '', d.username ?? '')}>Restore</button>
								<button class="btn danger sm" type="button" onclick={() => erase(d.id ?? '', d.username ?? '')}>Erase now</button>
							</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
		<p class="hint more">Erase now asks you to type the username. It cannot be undone.</p>
	{:else}
		<p class="empty">No accounts are waiting to be erased.</p>
	{/if}
</section>

<style>
	.msg {
		margin: 0 0 14px;
	}
	td strong {
		font-weight: 600;
	}
	.end {
		text-align: right;
		white-space: nowrap;
	}
	.more {
		margin-top: 14px;
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
