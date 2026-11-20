<!-- AC7 Your data: download a copy, or delete the account (a protected change, AC8, confirmed by typing the
     username). -->
<script lang="ts">
	import { api, ApiError } from '#lib/api/client.ts';
	import Icon from '#lib/components/Icon.svelte';
	import { messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const username = $derived(data.me.username);

	let typed = $state('');
	let error = $state('');
	let busy = $state(false);

	async function remove(event: SubmitEvent) {
		event.preventDefault();
		error = '';
		if (typed.trim() !== username) {
			error = `Type your username, ${username}, exactly.`;
			return;
		}
		busy = true;
		try {
			await api.delete('/me', { body: { username }, reason: 'delete your account' });
			// The session is gone; the sign-in page says nothing about the account, which is now disabled.
			location.assign('/login');
		} catch (e) {
			if (e instanceof ApiError && e.code === 'last_admin') error = 'You are the only administrator. Make someone else an administrator first.';
			else if (!(e instanceof ApiError && e.code === 'cancelled')) error = messageOf(e);
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>Your data · Guardian</title></svelte:head>

<div class="ph"><h1>Your data</h1><p>Take a copy of what Guardian keeps about you, or delete your account.</p></div>

<section class="card">
	<h2 class="sec-h">Download your data</h2>
	<p class="text">Your profile, groups, sessions, connected apps and your own audit entries, as a JSON file.</p>
	<a class="btn" href="/api/v1/me/export" download data-sveltekit-reload><Icon name="data" />Download</a>
</section>

<form class="card danger-card" onsubmit={remove} novalidate>
	<h2 class="sec-h">Delete your account</h2>
	<ul>
		<li>You are signed out everywhere at once.</li>
		<li>The account is erased after 30 days. An administrator can restore it until then.</li>
		<li>Apps may keep data of their own. Ask them to delete it.</li>
	</ul>
	<div class="confirm">
		<label class="lbl" for="cu">Type your username, <strong>{username}</strong>, to confirm</label>
		<input class="in" id="cu" bind:value={typed} autocomplete="off" autocapitalize="none" spellcheck="false" aria-invalid={error ? 'true' : undefined} aria-describedby={error ? 'cu-err' : undefined} />
	</div>
	{#if error}<p class="err-msg msg" id="cu-err" role="alert">{error}</p>{/if}
	<div class="end"><button class="btn danger" type="submit" disabled={busy}>Delete my account</button></div>
</form>

<style>
	.text {
		margin: 14px 0 16px;
	}
	.danger-card {
		border-color: var(--danger);
	}
	ul {
		margin: 14px 0 18px;
		padding-left: 20px;
		display: flex;
		flex-direction: column;
		gap: 6px;
	}
	.confirm {
		max-width: 360px;
	}
	.msg {
		margin: 16px 0 0;
	}
	.end {
		display: flex;
		justify-content: flex-end;
		margin-top: 18px;
	}
</style>
