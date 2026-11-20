<!-- AC4 Connected apps: the apps the user has signed in to, what each can see, and Remove access (a
     protected change, AC8). -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import AppLogo from '#lib/components/AppLogo.svelte';
	import { formatDate, formatWhen, messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const apps = $derived(data.apps);

	let error = $state('');
	let done = $state('');

	async function remove(id: string, name: string) {
		error = done = '';
		const ok = await askConfirm({
			title: `Remove access for ${name}?`,
			message: `You are signed out of ${name}, and it asks for your permission again the next time you sign in to it.`,
			confirm: 'Remove access',
			danger: true
		});
		if (!ok) return;
		try {
			await api.delete('/me/apps/{app}', { path: { app: id }, reason: `remove access for ${name}` });
			done = `${name} no longer has access.`;
			await refreshAll();
		} catch (e) {
			if (!(e instanceof ApiError && e.code === 'cancelled')) error = messageOf(e);
		}
	}
</script>

<svelte:head><title>Connected apps · Guardian</title></svelte:head>

<div class="ph"><h1>Connected apps</h1><p>Apps you have signed in to, and what each can see.</p></div>

<section class="card">
	<h2 class="sec-h">Apps</h2>
	{#if done}<p class="ok-msg msg" role="status">{done}</p>{/if}
	{#if error}<p class="err-msg msg" role="alert">{error}</p>{/if}
	{#if apps.length}
		<div class="list">
			{#each apps as app (app.id)}
				<div class="row">
					<span class="app">
						<AppLogo name={app.display_name} logo={app.logo_url} />
						<span class="body">
							<strong>{app.display_name}</strong>
							<span class="hint block">First used {formatDate(app.first_used_at)} · last used {formatWhen(app.last_used_at)}</span>
							<ul class="sees">
								{#each app.sees as line (line)}<li>{line}</li>{/each}
							</ul>
						</span>
					</span>
					<button class="btn alt" type="button" onclick={() => remove(app.id, app.display_name)}>Remove access</button>
				</div>
			{/each}
		</div>
		<p class="hint">Removing access signs you out of the app. It asks you again next time you sign in.</p>
	{:else}
		<p class="empty">You have not signed in to any apps yet.</p>
	{/if}
</section>

<style>
	.msg {
		margin: 14px 0 0;
	}
	.list {
		margin-top: 6px;
	}
	.row {
		align-items: flex-start;
	}
	.app {
		display: flex;
		gap: 14px;
		align-items: flex-start;
		flex: 1 1 360px;
	}
	.body {
		flex: 1;
		min-width: 0;
	}
	.body strong {
		font-weight: 600;
	}
	.block {
		display: block;
		margin: 2px 0 8px;
	}
	.sees {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 4px;
		font-size: 14px;
	}
	.sees li {
		display: flex;
		gap: 8px;
		align-items: center;
	}
	.sees li::before {
		content: '';
		width: 6px;
		height: 6px;
		transform: rotate(45deg);
		background: var(--accent);
		flex: none;
	}
	.empty {
		margin: 14px 0 0;
		padding: 24px;
		text-align: center;
		border: 1px dashed var(--line);
		border-radius: 8px;
		color: var(--mute);
	}
</style>
