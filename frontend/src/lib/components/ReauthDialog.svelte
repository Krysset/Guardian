<!-- AC8 Confirm it's you: asked before a protected change when the session has not confirmed who its user is
     within the last 5 minutes. The API client opens it (reauth.svelte.ts) and sends the change again once
     POST /me/reauth succeeds. -->
<script lang="ts">
	import { tick } from 'svelte';
	import { api, ApiError } from '#lib/api/client.ts';
	import { reauth } from '#lib/reauth.svelte.ts';
	import { keyError, keysSupported, useKey } from '#lib/webauthn.ts';
	import Icon from './Icon.svelte';

	let { hasTotp, hasKeys }: { hasTotp: boolean; hasKeys: boolean } = $props();

	let dialog: HTMLDialogElement | undefined = $state();
	let input: HTMLInputElement | undefined = $state();
	let method = $state<'password' | 'code' | 'key'>('password');
	const useCode = $derived(method === 'code');
	let value = $state('');
	let show = $state(false);
	let error = $state('');
	let busy = $state(false);

	const pending = $derived(reauth.pending);

	$effect(() => {
		if (pending && dialog && !dialog.open) {
			method = 'password';
			value = '';
			error = '';
			show = false;
			dialog.showModal();
			tick().then(() => input?.focus());
		} else if (!pending && dialog?.open) {
			dialog.close();
		}
	});

	async function confirm(event: SubmitEvent) {
		event.preventDefault();
		if (!pending || busy) return;
		if (method === 'key') return confirmWithKey();
		if (!value.trim()) {
			error = useCode ? 'Enter the 6-digit code from your authenticator app.' : 'Enter your password.';
			return;
		}
		busy = true;
		error = '';
		try {
			await api.post('/me/reauth', { body: useCode ? { code: value.replace(/\s/g, '') } : { password: value } });
			pending.done(true);
		} catch (e) {
			error = e instanceof ApiError ? e.message + (e.message.endsWith('.') ? '' : '.') : 'Something went wrong. Try again.';
			value = '';
			input?.focus();
		} finally {
			busy = false;
		}
	}

	async function confirmWithKey() {
		if (!pending) return;
		busy = true;
		error = '';
		try {
			const begun = await api.post('/me/reauth/key', {});
			const credential = await useKey(begun.options);
			await api.post('/me/reauth', { body: { key: { token: begun.token, credential } } });
			pending.done(true);
		} catch (e) {
			error = keyError(e) ?? (e instanceof ApiError ? e.message + (e.message.endsWith('.') ? '' : '.') : 'Something went wrong. Try again.');
		} finally {
			busy = false;
		}
	}

	function cancel() {
		pending?.done(false);
	}

	function switchTo(next: typeof method) {
		method = next;
		value = '';
		error = '';
		tick().then(() => input?.focus());
	}

	const choices = [
		['password', 'Use your password'],
		['code', 'Use a two-factor code'],
		['key', 'Use a security key']
	] as const;
	const others = $derived(choices.filter(([m]) => m !== method && (m !== 'code' || hasTotp) && (m !== 'key' || (hasKeys && keysSupported()))));
</script>

<!-- Escape fires "cancel"; the change is then not made. -->
<dialog bind:this={dialog} aria-labelledby="reauth-h" oncancel={cancel}>
	{#if pending}
		<form onsubmit={confirm} novalidate>
			<h2 id="reauth-h">Confirm it's you</h2>
			<p class="what">Confirm it's you to {pending.reason}.</p>
			{#if method === 'key'}
				<p class="key"><Icon name="key" />When your browser asks, touch your key or unlock your passkey.</p>
			{:else if useCode}
				<label class="lbl" for="reauth-code">Code from your authenticator app</label>
				<input
					bind:this={input}
					bind:value
					class="in code"
					id="reauth-code"
					inputmode="numeric"
					autocomplete="one-time-code"
					maxlength="7"
					aria-invalid={error ? 'true' : undefined}
					aria-describedby={error ? 'reauth-err' : undefined}
				/>
			{:else}
				<label class="lbl" for="reauth-pw">Password</label>
				<div class="pw">
					<input
						bind:this={input}
						bind:value
						class="in"
						id="reauth-pw"
						type={show ? 'text' : 'password'}
						autocomplete="current-password"
						aria-invalid={error ? 'true' : undefined}
						aria-describedby={error ? 'reauth-err' : undefined}
					/>
					<button
						class="btn alt sm"
						type="button"
						aria-label={show ? 'Hide password' : 'Show password'}
						aria-pressed={show}
						onclick={() => (show = !show)}><Icon name="eye" /></button
					>
				</div>
			{/if}
			{#if error}<p class="err-t" id="reauth-err" role="alert">{error}</p>{/if}
			{#if others.length}
				<p class="hint others">
					{#each others as [m, label] (m)}<button class="link-btn" type="button" onclick={() => switchTo(m)}>{label}</button>{/each}
				</p>
			{/if}
			<div class="actions">
				<button class="btn alt" type="button" onclick={cancel}>Cancel</button>
				<button class="btn" type="submit" disabled={busy}>{method === 'key' ? 'Use security key' : 'Confirm'}</button>
			</div>
			<p class="hint">You won't be asked again for 5 minutes.</p>
		</form>
	{/if}
</dialog>

<style>
	dialog {
		width: min(480px, calc(100% - 32px));
		box-sizing: border-box;
		margin: 150px auto auto;
		background: var(--surface);
		color: var(--ink);
		border-radius: 12px;
		border: 1px solid var(--line);
		box-shadow: 0 30px 80px -20px rgba(0, 0, 0, 0.55);
		padding: 26px 28px;
	}
	dialog::backdrop {
		background: rgba(6, 18, 22, 0.45);
	}
	h2 {
		font: 600 20px/1.3 Figtree, system-ui, sans-serif;
		margin: 0 0 6px;
	}
	.what {
		margin: 0 0 18px;
		color: var(--mute);
	}
	.pw {
		display: flex;
		align-items: center;
		gap: 6px;
		height: 42px;
		padding-right: 6px;
		border: 1px solid var(--line);
		border-radius: 6px;
		background: var(--field);
	}
	.pw:focus-within {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent);
	}
	.pw .in {
		border: 0;
		height: 40px;
		background: transparent;
		box-shadow: none;
	}
	.code {
		font: 500 18px ui-monospace, Menlo, Consolas, monospace;
		letter-spacing: 0.2em;
		max-width: 12em;
	}
	.key {
		display: flex;
		gap: 10px;
		align-items: center;
		margin: 0;
		padding: 12px 14px;
		border: 1px solid var(--line);
		border-radius: 8px;
	}
	.others {
		display: flex;
		flex-wrap: wrap;
		gap: 6px 18px;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
		margin-top: 22px;
	}
	@media (max-width: 760px) {
		dialog {
			margin-top: 60px;
		}
	}
</style>
