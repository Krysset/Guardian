<!-- AC3 Sessions: where the account is signed in. IP addresses are partly hidden until shown. Signing out
     a session is a protected change (AC8). -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import Icon from '#lib/components/Icon.svelte';
	import { formatLastActive, formatWhen, maskIP, messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const sessions = $derived(data.sessions);
	const others = $derived(sessions.filter((s) => !s.current).length);

	let shown = $state<Record<string, boolean>>({});
	let error = $state('');
	let done = $state('');

	const cancelled = (e: unknown) => e instanceof ApiError && e.code === 'cancelled';

	async function signOut(id: string, browser: string) {
		error = done = '';
		try {
			await api.delete('/me/sessions/{session}', { path: { session: id }, reason: 'sign out a session' });
			done = `${browser} is signed out.`;
			await refreshAll();
		} catch (e) {
			if (!cancelled(e)) error = messageOf(e);
		}
	}

	async function signOutOthers() {
		error = done = '';
		const ok = await askConfirm({
			title: 'Sign out everywhere else?',
			message: `${others === 1 ? 'One other session ends' : `${others} other sessions end`}, and the apps used there must sign in again. This device stays signed in.`,
			confirm: 'Sign out everywhere else'
		});
		if (!ok) return;
		try {
			await api.delete('/me/sessions', { reason: 'sign out everywhere else' });
			done = 'You are signed out everywhere else.';
			await refreshAll();
		} catch (e) {
			if (!cancelled(e)) error = messageOf(e);
		}
	}
</script>

<svelte:head><title>Sessions · Guardian</title></svelte:head>

<div class="ph"><h1>Sessions</h1><p>Where your account is signed in.</p></div>

<section class="card">
	<h2 class="sec-h">Signed in</h2>
	{#if done}<p class="ok-msg msg" role="status">{done}</p>{/if}
	{#if error}<p class="err-msg msg" role="alert">{error}</p>{/if}
	<div class="scroll">
		<table class="tbl">
			<thead><tr><th>Browser and system</th><th>IP address</th><th>Signed in</th><th>Last active</th><th><span class="visually-hidden">Actions</span></th></tr></thead>
			<tbody>
				{#each sessions as s (s.id)}
					<tr>
						<td><strong>{s.browser}</strong>{#if s.current}<span class="badge here">This device</span>{/if}</td>
						<td>
							<span class="ip">
								<code>{shown[s.id] ? s.ip_address || 'Unknown' : maskIP(s.ip_address)}</code>
								{#if s.ip_address}
									<button class="btn alt sm eye" type="button" aria-label={shown[s.id] ? 'Hide IP address' : 'Show IP address'} aria-pressed={!!shown[s.id]} onclick={() => (shown[s.id] = !shown[s.id])}><Icon name="eye" size={16} /></button>
								{/if}
							</span>
						</td>
						<td>{formatWhen(s.created_at)}</td>
						<td>{formatLastActive(s.last_seen_at)}</td>
						<td class="end">
							{#if !s.current}<button class="btn alt sm" type="button" onclick={() => signOut(s.id, s.browser)}>Sign out</button>{/if}
						</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>
	<div class="foot">
		<span class="hint">Don't recognise one? Sign it out and change your password.</span>
		{#if others > 0}<button class="btn alt" type="button" onclick={signOutOthers}>Sign out everywhere else</button>{/if}
	</div>
</section>

<style>
	.msg {
		margin: 14px 0 0;
	}
	.scroll {
		margin-top: 14px;
	}
	td strong {
		font-weight: 600;
	}
	.here {
		color: var(--ok);
		margin-left: 8px;
	}
	.ip {
		display: inline-flex;
		gap: 6px;
		align-items: center;
		white-space: nowrap;
	}
	.eye {
		height: 26px;
		padding: 0 6px;
	}
	.end {
		text-align: right;
	}
	.foot {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 16px;
		margin-top: 18px;
		flex-wrap: wrap;
	}
	.foot .hint {
		margin: 0;
	}
</style>
