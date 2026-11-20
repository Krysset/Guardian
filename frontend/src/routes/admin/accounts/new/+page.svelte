<!-- AD3 New account: username, a first password typed twice, and an optional email address (counts as
     confirmed). The person must choose their own password at the first sign-in. -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import PasswordField from '#lib/components/PasswordField.svelte';
	import { messageOf } from '#lib/format.ts';

	let username = $state('');
	let email = $state('');
	let password = $state('');
	let password2 = $state('');
	let errors = $state<{ username?: string; email?: string; password?: string; password2?: string; form?: string }>({});
	let busy = $state(false);

	async function create(event: SubmitEvent) {
		event.preventDefault();
		const e: typeof errors = {};
		if (!/^[A-Za-z0-9._-]{3,64}$/.test(username.trim())) e.username = 'Use 3–64 letters, digits, dots, dashes or underscores.';
		if (email.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) e.email = 'Enter an address such as name@example.com, or leave it empty.';
		if (password.length < 10) e.password = 'Use at least 10 characters.';
		else if (password !== password2) e.password2 = 'The passwords do not match.';
		errors = e;
		if (Object.keys(e).length) return;
		busy = true;
		try {
			const account = await api.post('/accounts', {
				body: { username: username.trim(), password, ...(email.trim() ? { email: email.trim() } : {}) }
			});
			await refreshAll();
			await goto(`/admin/accounts/${account.id}`);
		} catch (err) {
			if (err instanceof ApiError && err.code === 'email_taken') errors = { email: 'That email address is in use.' };
			else if (err instanceof ApiError && err.code === 'username_taken') errors = { username: 'That username is taken.' };
			else errors = { form: messageOf(err) };
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>New account · Guardian</title></svelte:head>

<div class="ph">
	<p class="crumb"><a href="/admin/accounts">Accounts</a> / New</p>
	<h1>New account</h1>
	<p>The account must choose its own password at the first sign-in.</p>
</div>

<form class="card" onsubmit={create} novalidate>
	<h2 class="sec-h">Account</h2>
	<div class="grid2 fields">
		<div>
			<label class="lbl" for="nu">Username</label>
			<input class="in" id="nu" bind:value={username} autocomplete="off" autocapitalize="none" spellcheck="false" aria-invalid={errors.username ? 'true' : undefined} aria-describedby="nu-hint" />
			{#if errors.username}<p class="err-t" id="nu-hint">{errors.username}</p>
			{:else}<p class="hint" id="nu-hint">3–64 letters, digits, dots, dashes or underscores.</p>{/if}
		</div>
		<div>
			<label class="lbl" for="ne">Email <span class="optional">(optional)</span></label>
			<input class="in" id="ne" type="email" bind:value={email} placeholder="name@example.com" autocomplete="off" aria-invalid={errors.email ? 'true' : undefined} aria-describedby="ne-hint" />
			{#if errors.email}<p class="err-t" id="ne-hint">{errors.email}</p>
			{:else}<p class="hint" id="ne-hint">Counts as confirmed.</p>{/if}
		</div>
		<PasswordField id="p1" label="Password" bind:value={password} error={errors.password} />
		<PasswordField id="p2" label="Password again" bind:value={password2} error={errors.password2} />
	</div>
	<p class="hint">At least 10 characters. Give it to the person yourself.</p>
	{#if errors.form}<p class="err-msg msg" role="alert">{errors.form}</p>{/if}
	<div class="actions">
		<a class="btn alt" href="/admin/accounts">Cancel</a>
		<button class="btn" type="submit" disabled={busy}>Create</button>
	</div>
</form>

<style>
	.fields {
		margin-top: 14px;
	}
	.optional {
		color: var(--mute);
		font-weight: 400;
	}
	.msg {
		margin: 14px 0 0;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
		margin-top: 20px;
	}
</style>
