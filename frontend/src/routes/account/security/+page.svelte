<!-- AC2 Security: the password, the authenticator app, security keys and passkeys, and the recovery codes.
     Every change here is protected (AC8), except renaming a key. -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { tick } from 'svelte';
	import { api, ApiError } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import Icon from '#lib/components/Icon.svelte';
	import PasswordField from '#lib/components/PasswordField.svelte';
	import RecoveryCodes from '#lib/components/RecoveryCodes.svelte';
	import { formatDate, formatWhen, messageOf } from '#lib/format.ts';
	import { createKey, keyError, keysSupported } from '#lib/webauthn.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const mfa = $derived(data.me.mfa);
	const keys = $derived(mfa.security_keys ?? []);
	// How many two-factor methods there are: an account that must use two-factor keeps at least one.
	const methods = $derived((mfa.totp ? 1 : 0) + keys.length);
	const isOn = $derived(methods > 0);
	const lastRequired = $derived(Boolean(mfa.required) && methods === 1);

	const cancelled = (e: unknown) => e instanceof ApiError && e.code === 'cancelled';

	// Password
	let password = $state('');
	let password2 = $state('');
	let pwError = $state<{ password?: string; password2?: string; form?: string }>({});
	let pwDone = $state(false);
	let pwBusy = $state(false);

	async function changePassword(event: SubmitEvent) {
		event.preventDefault();
		pwDone = false;
		const e: typeof pwError = {};
		if (password.length < 10) e.password = 'Use at least 10 characters.';
		else if (password !== password2) e.password2 = 'The passwords do not match.';
		pwError = e;
		if (Object.keys(e).length) return;
		pwBusy = true;
		try {
			await api.put('/me/password', { body: { new_password: password }, reason: 'change your password' });
			password = password2 = '';
			pwDone = true;
		} catch (err) {
			if (!cancelled(err)) pwError = { form: messageOf(err) };
		} finally {
			pwBusy = false;
		}
	}

	// Authenticator app: start (secret and QR code), confirm a code, then save the recovery codes.
	type Setup =
		| { step: 'scan'; token: string; secret: string; qr: string }
		| { step: 'codes'; token: string; codes: string[]; kind: 'totp' | 'key' | 'renew' }
		| { step: 'name' };
	let setup = $state<Setup | null>(null);
	let code = $state('');
	let mfaError = $state('');
	let mfaDone = $state('');
	let mfaBusy = $state(false);
	let codeInput: HTMLInputElement | undefined = $state();

	async function startSetup() {
		mfaError = mfaDone = '';
		mfaBusy = true;
		try {
			const r = await api.post('/me/mfa/totp', { reason: 'set up an authenticator app' });
			setup = { step: 'scan', token: r.setup_token ?? '', secret: r.secret ?? '', qr: r.qr_code ?? '' };
			code = '';
			await tick();
			codeInput?.focus();
		} catch (e) {
			if (!cancelled(e)) mfaError = messageOf(e);
		} finally {
			mfaBusy = false;
		}
	}

	async function confirmCode(event: SubmitEvent) {
		event.preventDefault();
		if (setup?.step !== 'scan') return;
		mfaError = '';
		if (!/^\d{6}$/.test(code.replace(/\s/g, ''))) {
			mfaError = 'Enter the 6-digit code your app shows.';
			return;
		}
		mfaBusy = true;
		try {
			const r = await api.post('/me/mfa/totp/confirm', { body: { setup_token: setup.token, code: code.replace(/\s/g, '') } });
			setup = { step: 'codes', token: r.setup_token ?? '', codes: r.recovery_codes ?? [], kind: 'totp' };
		} catch (e) {
			mfaError = messageOf(e);
		} finally {
			mfaBusy = false;
		}
	}

	async function renewCodes() {
		mfaError = mfaDone = '';
		const ok = await askConfirm({
			title: 'Make new recovery codes?',
			message: 'Your current codes keep working until you have saved the new ones.',
			confirm: 'Make new codes'
		});
		if (!ok) return;
		try {
			const r = await api.post('/me/mfa/recovery-codes', { reason: 'make new recovery codes' });
			setup = { step: 'codes', token: r.setup_token ?? '', codes: r.recovery_codes ?? [], kind: 'renew' };
		} catch (e) {
			if (!cancelled(e)) mfaError = messageOf(e);
		}
	}

	async function finishCodes(answer: string) {
		if (setup?.step !== 'codes') return;
		const body = { setup_token: setup.token, recovery_code: answer };
		if (setup.kind === 'renew') await api.post('/me/mfa/recovery-codes/finish', { body });
		else await api.post('/me/mfa/finish', { body });
		mfaDone = setup.kind === 'renew' ? 'Your new recovery codes are in place. The old ones no longer work.' : 'Two-factor is on.';
		setup = null;
		await refreshAll();
	}

	// Removing the last method turns two-factor off and takes the recovery codes with it: say so plainly.
	function removalWarning(what: string) {
		return methods === 1
			? { title: 'Turn off two-factor?', message: `This removes ${what} and your recovery codes, your last way back in without your password. Signing in then needs only your password.`, confirm: 'Turn off', danger: true }
			: { title: `Remove ${what}?`, message: 'Your other two-factor methods and your recovery codes stay.', confirm: 'Remove', danger: true };
	}

	async function removeApp() {
		mfaError = mfaDone = '';
		if (!(await askConfirm(removalWarning('your authenticator app')))) return;
		try {
			await api.delete('/me/mfa/totp', { reason: 'remove your authenticator app' });
			mfaDone = methods === 1 ? 'Two-factor is off.' : 'The authenticator app is removed.';
			await refreshAll();
		} catch (e) {
			if (!cancelled(e)) mfaError = messageOf(e);
		}
	}

	// Security keys and passkeys: name it, the browser's dialog, then (for the first method) the recovery codes.
	let keyName = $state('');
	let nameInput: HTMLInputElement | undefined = $state();

	async function askName() {
		mfaError = mfaDone = '';
		keyName = '';
		setup = { step: 'name' };
		await tick();
		nameInput?.focus();
	}

	async function addKey(event: SubmitEvent) {
		event.preventDefault();
		mfaError = '';
		if (keyName.trim().length > 64) {
			mfaError = 'Use at most 64 characters.';
			return;
		}
		mfaBusy = true;
		try {
			const begun = await api.post('/me/mfa/keys', { reason: 'add a security key' });
			const credential = await createKey(begun.options);
			const r = await api.post('/me/mfa/keys/finish', { body: { setup_token: begun.setup_token, credential, name: keyName.trim() } });
			if ('recovery_codes' in r && r.recovery_codes) {
				setup = { step: 'codes', token: r.setup_token ?? '', codes: r.recovery_codes, kind: 'key' };
			} else {
				setup = null;
				mfaDone = 'Security key added.';
				await refreshAll();
			}
		} catch (e) {
			if (!cancelled(e)) mfaError = keyError(e) ?? messageOf(e);
		} finally {
			mfaBusy = false;
		}
	}

	let renaming = $state<string | null>(null);
	let newName = $state('');

	async function rename(event: SubmitEvent, id: string) {
		event.preventDefault();
		mfaError = mfaDone = '';
		if (!newName.trim() || newName.trim().length > 64) {
			mfaError = 'Give the key a name of at most 64 characters.';
			return;
		}
		try {
			await api.patch('/me/mfa/keys/{key}', { path: { key: id }, body: { name: newName.trim() } });
			renaming = null;
			await refreshAll();
		} catch (e) {
			mfaError = messageOf(e);
		}
	}

	async function removeKey(id: string, name: string) {
		mfaError = mfaDone = '';
		if (!(await askConfirm(removalWarning(`“${name}”`)))) return;
		try {
			await api.delete('/me/mfa/keys/{key}', { path: { key: id }, reason: 'remove a security key' });
			mfaDone = methods === 1 ? 'Two-factor is off.' : `“${name}” is removed.`;
			await refreshAll();
		} catch (e) {
			if (!cancelled(e)) mfaError = messageOf(e);
		}
	}
</script>

<svelte:head><title>Security · Guardian</title></svelte:head>

<div class="ph"><h1>Security</h1><p>How you sign in, and how to get back in if you lose something.</p></div>

<form class="card" onsubmit={changePassword} novalidate>
	<h2 class="sec-h">Password</h2>
	<p class="hint intro">Use one you do not use anywhere else.</p>
	<input class="visually-hidden" type="text" autocomplete="username" value={data.me.username} readonly tabindex="-1" aria-hidden="true" />
	<div class="grid2">
		<PasswordField id="np" label="New password" bind:value={password} error={pwError.password} />
		<PasswordField id="np2" label="New password again" bind:value={password2} error={pwError.password2} />
	</div>
	<p class="hint">At least 10 characters. Changing it signs you out everywhere else.</p>
	{#if pwError.form}<p class="err-msg msg" role="alert">{pwError.form}</p>{/if}
	{#if pwDone}<p class="ok-msg msg" role="status">Your password is changed. Your other sessions are signed out.</p>{/if}
	<div class="end"><button class="btn" type="submit" disabled={pwBusy}>Change password</button></div>
</form>

<section class="card">
	<h2 class="sec-h">Two-factor</h2>
	<p class="hint intro">A second step after your password.</p>
	{#if mfaDone}<p class="ok-msg msg" role="status">{mfaDone}</p>{/if}
	{#if mfaError && !setup}<p class="err-msg msg" role="alert">{mfaError}</p>{/if}

	{#if setup?.step === 'scan'}
		<form class="setup" onsubmit={confirmCode} novalidate>
			<ol>
				<li>
					Scan this with your authenticator app.
					<img class="qr" src={setup.qr} alt="QR code for your authenticator app" width="200" height="200" />
					<span class="hint">Can't scan it? Type this key instead: <code class="key">{setup.secret.replace(/(.{4})/g, '$1 ').trim()}</code></span>
				</li>
				<li>
					<label for="totp-code">Enter the code it shows.</label>
					<div class="answer">
						<input bind:this={codeInput} bind:value={code} class="in code" id="totp-code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" aria-invalid={mfaError ? 'true' : undefined} aria-describedby={mfaError ? 'totp-err' : undefined} />
						<button class="btn" type="submit" disabled={mfaBusy}>Continue</button>
						<button class="btn alt" type="button" onclick={() => ((setup = null), (mfaError = ''))}>Cancel</button>
					</div>
					{#if mfaError}<p class="err-t" id="totp-err" role="alert">{mfaError}</p>{/if}
				</li>
			</ol>
		</form>
	{:else if setup?.step === 'codes'}
		<RecoveryCodes codes={setup.codes} finish={finishCodes} cancel={() => (setup = null)} />
	{:else if setup?.step === 'name'}
		<form class="setup" onsubmit={addKey} novalidate>
			<label class="lbl" for="key-name">Name it, so you can tell your keys apart</label>
			<div class="answer">
				<input bind:this={nameInput} bind:value={keyName} class="in name" id="key-name" maxlength="64" placeholder="Security key" autocomplete="off" aria-invalid={mfaError ? 'true' : undefined} aria-describedby={mfaError ? 'key-err' : 'key-hint'} />
				<button class="btn" type="submit" disabled={mfaBusy}><Icon name="key" />Add</button>
				<button class="btn alt" type="button" onclick={() => ((setup = null), (mfaError = ''))}>Cancel</button>
			</div>
			{#if mfaError}<p class="err-t" id="key-err" role="alert">{mfaError}</p>
			{:else}<p class="hint" id="key-hint">Your browser then asks you to touch the key, or to save a passkey on this device or your phone.</p>{/if}
		</form>
	{:else}
		{#if isOn}
			<div class="note">
				<strong>Two-factor is on.</strong>
				{#if mfa.required}{mfa.required_reason}{/if}
			</div>
		{:else if mfa.required}
			<div class="note warn"><strong>Two-factor is off, but you need it.</strong> {mfa.required_reason}</div>
		{:else}
			<div class="note"><strong>Two-factor is off.</strong> Turn it on so a stolen password is not enough to sign in.</div>
		{/if}
		<div class="row">
			<span class="what">
				<span class="logo-t"><Icon name="shield" /></span>
				<span>
					<strong>Authenticator app</strong>
					<span class="hint block">{mfa.totp ? `Set up ${formatDate(mfa.totp_added_at)}` : 'Not set up'}</span>
				</span>
			</span>
			{#if mfa.totp}
				<span class="buttons">
					<button class="btn alt" type="button" onclick={startSetup} disabled={mfaBusy}>Replace</button>
					<button class="btn alt" type="button" onclick={removeApp} disabled={lastRequired} title={lastRequired ? 'You must keep one two-factor method' : undefined}>Remove</button>
				</span>
			{:else}
				<button class="btn alt" type="button" onclick={startSetup} disabled={mfaBusy}>Set up</button>
			{/if}
		</div>
		{#each keys as k (k.id)}
			<div class="row">
				{#if renaming === k.id}
					<form class="rename" onsubmit={(e) => rename(e, k.id)} novalidate>
						<label class="visually-hidden" for="rn-{k.id}">New name</label>
						<input class="in" id="rn-{k.id}" bind:value={newName} maxlength="64" autocomplete="off" />
						<button class="btn" type="submit">Save</button>
						<button class="btn alt" type="button" onclick={() => (renaming = null)}>Cancel</button>
					</form>
				{:else}
					<span class="what">
						<span class="logo-t"><Icon name="key" /></span>
						<span>
							<strong>{k.name}</strong>
							<span class="hint block">{k.passkey ? 'Passkey' : 'Security key'} · added {formatDate(k.created_at)}{k.last_used_at ? ` · last used ${formatWhen(k.last_used_at)}` : ''}</span>
						</span>
					</span>
					<span class="buttons">
						<button class="btn alt" type="button" onclick={() => ((renaming = k.id), (newName = k.name))}>Rename</button>
						<button class="btn alt" type="button" onclick={() => removeKey(k.id, k.name)} disabled={lastRequired} title={lastRequired ? 'You must keep one two-factor method' : undefined}>Remove</button>
					</span>
				{/if}
			</div>
		{/each}
		<div class="row">
			<span class="what">
				<span class="logo-t"><Icon name="key" /></span>
				<span>
					<strong>{keys.length ? 'Add another security key or passkey' : 'Security keys and passkeys'}</strong>
					<span class="hint block">{keysSupported() ? 'A passkey also signs you in without your password.' : "This browser can't use security keys."}</span>
				</span>
			</span>
			<button class="btn alt" type="button" onclick={askName} disabled={mfaBusy || !keysSupported()}><Icon name="plus" />Add</button>
		</div>
		{#if isOn}
			<div class="row">
				<span class="what">
					<span class="logo-t"><Icon name="list" /></span>
					<span>
						<strong>Recovery codes</strong>
						<span class="hint block">{mfa.recovery_codes_left ?? 0} of 10 left. Each works once.</span>
					</span>
				</span>
				<button class="btn alt" type="button" onclick={renewCodes}>Make new codes</button>
			</div>
		{/if}
	{/if}
</section>

<style>
	.intro {
		margin: 0 0 18px;
	}
	.msg {
		margin: 14px 0 0;
	}
	.end {
		display: flex;
		justify-content: flex-end;
		margin-top: 18px;
	}
	.note {
		margin-bottom: 8px;
	}
	.note.warn {
		background: var(--warnbg);
		color: var(--warn);
	}
	.card > .msg:first-of-type {
		margin: 0 0 14px;
	}
	.what {
		display: flex;
		gap: 12px;
		align-items: center;
	}
	.logo-t {
		width: 36px;
		height: 36px;
		border-radius: 9px;
		background: var(--tile);
		display: grid;
		place-items: center;
		color: var(--accent);
		flex: none;
	}
	.block {
		display: block;
		margin: 0;
	}
	.buttons {
		display: flex;
		gap: 10px;
	}
	.setup ol {
		margin: 0;
		padding-left: 20px;
		display: flex;
		flex-direction: column;
		gap: 18px;
	}
	.setup li > span,
	.qr {
		display: block;
		margin-top: 10px;
	}
	.qr {
		background: #fff;
		padding: 8px;
		border-radius: 8px;
	}
	.key {
		font: 500 14px ui-monospace, Menlo, Consolas, monospace;
		color: var(--ink);
	}
	.answer {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		margin-top: 8px;
	}
	.code {
		font: 500 18px ui-monospace, Menlo, Consolas, monospace;
		letter-spacing: 0.2em;
		max-width: 10em;
	}
	.name {
		flex: 1 1 220px;
		max-width: 320px;
	}
	.rename {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
		width: 100%;
	}
	.rename .in {
		flex: 1 1 200px;
		max-width: 320px;
	}
</style>
