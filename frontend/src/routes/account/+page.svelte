<!-- AC1 Profile: picture, names, username, language and time zone, and the email address (masked until
     shown). The username and the email address are protected changes (AC8). -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, ApiError, type Schema } from '#lib/api/client.ts';
	import Icon from '#lib/components/Icon.svelte';
	import { initial, maskEmail, messageOf, formatWhen } from '#lib/format.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const me = $derived(data.me);

	type Fields = {
		username: string;
		display_name: string;
		given_name: string;
		family_name: string;
		picture_url: string;
		locale: string;
		zoneinfo: string;
	};

	function fromAccount(a: Schema<'Account'>): Fields {
		return {
			username: a.username,
			display_name: a.display_name ?? '',
			given_name: a.given_name ?? '',
			family_name: a.family_name ?? '',
			picture_url: a.picture_url ?? '',
			locale: a.locale ?? '',
			zoneinfo: a.zoneinfo ?? ''
		};
	}

	// The form starts from the account and stays as edited until saved or discarded.
	// svelte-ignore state_referenced_locally
	let saved = $state(fromAccount(data.me));
	// svelte-ignore state_referenced_locally
	let form = $state(fromAccount(data.me));
	let error = $state('');
	let fieldError = $state<Partial<Record<keyof Fields, string>>>({});
	let done = $state(false);
	let busy = $state(false);

	const changes = $derived(
		Object.fromEntries(Object.entries(form).filter(([k, v]) => v.trim() !== saved[k as keyof Fields])) as Partial<Fields>
	);
	const dirty = $derived(Object.keys(changes).length > 0);

	// Languages people commonly choose, the account's own and the browser's; named in the browser's language.
	const localeNames = new Intl.DisplayNames(undefined, { type: 'language' });
	const locales = $derived.by(() => {
		const tags = new Set(['en-GB', 'en-US', 'sv-SE', 'nb-NO', 'da-DK', 'fi-FI', 'de-DE', 'fr-FR', 'es-ES', 'it-IT', 'nl-NL', 'pl-PL', 'pt-BR', 'pt-PT', 'ja-JP', 'ko-KR', 'zh-CN']);
		for (const l of navigator.languages) if (l.includes('-')) tags.add(l);
		if (saved.locale) tags.add(saved.locale);
		const named = [...tags].map((tag) => {
			let name = tag;
			try {
				name = localeNames.of(tag) ?? tag;
			} catch {
				// not a valid tag: show it as it is
			}
			return { tag, name };
		});
		return named.sort((a, b) => a.name.localeCompare(b.name));
	});
	const zones = $derived.by(() => {
		const all = Intl.supportedValuesOf('timeZone');
		return saved.zoneinfo && !all.includes(saved.zoneinfo) ? [saved.zoneinfo, ...all] : all;
	});
	const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone;

	function validate(): boolean {
		const f: typeof fieldError = {};
		if (!/^[A-Za-z0-9._-]{3,64}$/.test(form.username.trim())) f.username = 'Use 3–64 letters, digits, dots, dashes or underscores.';
		if (form.picture_url.trim() && !/^https:\/\/\S+$/.test(form.picture_url.trim())) f.picture_url = 'Enter an https address, or leave it empty.';
		fieldError = f;
		return Object.keys(f).length === 0;
	}

	async function save(event: SubmitEvent) {
		event.preventDefault();
		done = false;
		error = '';
		if (!dirty || busy || !validate()) return;
		busy = true;
		try {
			const body = Object.fromEntries(Object.entries(changes).map(([k, v]) => [k, v.trim()]));
			const account = await api.patch('/me', { body, reason: 'change your username' });
			saved = fromAccount(account);
			form = fromAccount(account);
			done = true;
			await refreshAll();
		} catch (e) {
			if (e instanceof ApiError && e.code === 'cancelled') return;
			if (e instanceof ApiError && e.status === 409) fieldError = { username: 'That username is taken.' };
			else error = messageOf(e);
		} finally {
			busy = false;
		}
	}

	function discard() {
		form = { ...saved };
		fieldError = {};
		error = '';
		done = false;
	}

	// The email address: masked until shown; add or change it (a link to confirm), remove it, or cancel a change.
	let showEmail = $state(false);
	let editingEmail = $state(false);
	let newEmail = $state('');
	let emailError = $state('');
	let emailNote = $state('');
	let emailBusy = $state(false);
	const settings = $derived(me.email_settings);

	async function sendLink(event?: SubmitEvent, address = newEmail.trim()) {
		event?.preventDefault();
		emailError = '';
		emailNote = '';
		if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) {
			emailError = 'Enter an address such as name@example.com.';
			return;
		}
		emailBusy = true;
		try {
			await api.put('/me/email', { body: { email: address }, reason: 'change your email address' });
			editingEmail = false;
			newEmail = '';
			emailNote = `We sent a link to ${address}. Open it to confirm the address.`;
			await refreshAll();
		} catch (e) {
			if (!(e instanceof ApiError && e.code === 'cancelled')) emailError = messageOf(e);
		} finally {
			emailBusy = false;
		}
	}

	async function cancelPending() {
		emailError = '';
		emailNote = '';
		try {
			await api.delete('/me/email/pending');
			await refreshAll();
		} catch (e) {
			emailError = messageOf(e);
		}
	}

	async function removeEmail() {
		emailError = '';
		emailNote = '';
		const ok = await askConfirm({
			title: 'Remove your email address?',
			message: "Without one you can't reset a forgotten password yourself, and apps can't email you.",
			confirm: 'Remove',
			danger: true
		});
		if (!ok) return;
		try {
			await api.delete('/me/email', { reason: 'remove your email address' });
			showEmail = false;
			await refreshAll();
		} catch (e) {
			if (!(e instanceof ApiError && e.code === 'cancelled')) emailError = messageOf(e);
		}
	}
</script>

<svelte:head><title>Profile · Guardian</title></svelte:head>

<div class="ph"><h1>Profile</h1><p>Apps you allow to see your profile get these details.</p></div>

<form class="stack" onsubmit={save} novalidate>
	{#if done}<p class="ok-msg" role="status">Saved.</p>{/if}
	{#if error}<p class="err-msg" role="alert">{error}</p>{/if}

	<section class="card">
		<h2 class="sec-h">About you</h2>
		<div class="about">
			{#if saved.picture_url}
				<img class="avatar" src={saved.picture_url} alt="" referrerpolicy="no-referrer" />
			{:else}
				<div class="avatar" aria-hidden="true">{initial(form.display_name || form.username)}</div>
			{/if}
			<div class="fields">
				<div class="wide">
					<label class="lbl" for="pic">Picture address</label>
					<input class="in" id="pic" type="url" bind:value={form.picture_url} aria-invalid={fieldError.picture_url ? 'true' : undefined} aria-describedby="pic-hint" />
					{#if fieldError.picture_url}<p class="err-t" id="pic-hint">{fieldError.picture_url}</p>
					{:else}<p class="hint" id="pic-hint">An https address. Leave empty to use your initial.</p>{/if}
				</div>
				<div class="wide">
					<label class="lbl" for="dn">Display name</label>
					<input class="in" id="dn" maxlength="128" bind:value={form.display_name} autocomplete="nickname" />
				</div>
				<div>
					<label class="lbl" for="gn">Given name</label>
					<input class="in" id="gn" maxlength="128" bind:value={form.given_name} autocomplete="given-name" />
				</div>
				<div>
					<label class="lbl" for="fn">Family name</label>
					<input class="in" id="fn" maxlength="128" bind:value={form.family_name} autocomplete="family-name" placeholder="Optional" />
				</div>
			</div>
		</div>
	</section>

	<section class="card">
		<h2 class="sec-h">Username and email</h2>
		<p class="hint intro">Changing either asks you to confirm it's you first.</p>
		<div class="grid2">
			<div>
				<label class="lbl" for="un">Username</label>
				<input class="in" id="un" bind:value={form.username} autocomplete="username" autocapitalize="none" spellcheck="false" aria-invalid={fieldError.username ? 'true' : undefined} aria-describedby="un-hint" />
				{#if fieldError.username}<p class="err-t" id="un-hint">{fieldError.username}</p>
				{:else}<p class="hint" id="un-hint">3–64 letters, digits, dots, dashes or underscores.</p>{/if}
			</div>
			<div>
				<span class="lbl" id="email-l">Email</span>
				{#if me.email}
					<div class="mask" aria-labelledby="email-l">
						<span>{showEmail ? me.email : maskEmail(me.email)}</span>
						<button class="btn alt sm" type="button" aria-label={showEmail ? 'Hide email address' : 'Show email address'} aria-pressed={showEmail} onclick={() => (showEmail = !showEmail)}
							><Icon name="eye" />{showEmail ? 'Hide' : 'Show'}</button
						>
					</div>
					<div class="email-actions">
						<span class="badge ok">Confirmed</span>
						{#if settings.enabled}<button class="link-btn" type="button" onclick={() => ((editingEmail = !editingEmail), (emailError = ''))}>Change</button>{/if}
						{#if !settings.required}<button class="link-btn" type="button" onclick={removeEmail}>Remove</button>{/if}
					</div>
				{:else}
					<div class="mask"><span class="none">No email address</span></div>
					{#if settings.enabled}
						<div class="email-actions"><button class="link-btn" type="button" onclick={() => ((editingEmail = !editingEmail), (emailError = ''))}>Add one</button></div>
					{:else}
						<p class="hint">This Guardian sends no email, so an address can't be confirmed. An administrator can set one.</p>
					{/if}
				{/if}
				{#if settings.pending}
					<div class="note pending" role="status">
						<strong>{settings.pending}</strong> is waiting for confirmation{settings.pending_until ? ` until ${formatWhen(settings.pending_until)}` : ''}.
						<span class="email-actions">
							<button class="link-btn" type="button" onclick={() => sendLink(undefined, settings.pending ?? '')}>Send the link again</button>
							<button class="link-btn" type="button" onclick={cancelPending}>Cancel the change</button>
						</span>
					</div>
				{/if}
				{#if editingEmail}
					<!-- Inside the profile form, so not a form itself: Enter sends the link instead of saving the profile. -->
					<div class="email-edit">
						<label class="lbl" for="new-email">{me.email ? 'New address' : 'Email address'}</label>
						<input
							class="in"
							id="new-email"
							type="email"
							bind:value={newEmail}
							autocomplete="email"
							aria-invalid={emailError ? 'true' : undefined}
							aria-describedby="new-email-hint"
							onkeydown={(e) => {
								if (e.key === 'Enter') {
									e.preventDefault();
									sendLink();
								}
							}}
						/>
						{#if emailError}<p class="err-t" id="new-email-hint" role="alert">{emailError}</p>
						{:else}<p class="hint" id="new-email-hint">We send a link to it.{me.email ? ' It replaces the current address only when you open it.' : ''}</p>{/if}
						<div class="email-actions">
							<button class="btn sm" type="button" disabled={emailBusy} onclick={() => sendLink()}>Send link</button>
							<button class="btn alt sm" type="button" onclick={() => ((editingEmail = false), (emailError = ''))}>Cancel</button>
						</div>
					</div>
				{/if}
				{#if emailNote && !settings.pending}<p class="hint" role="status">{emailNote}</p>{/if}
				{#if emailError && !editingEmail}<p class="err-t" role="alert">{emailError}</p>{/if}
			</div>
		</div>
	</section>

	<section class="card">
		<h2 class="sec-h">Language and time</h2>
		<p class="hint intro">Apps use these to show dates and text the way you expect.</p>
		<div class="grid2">
			<div>
				<label class="lbl" for="lc">Language</label>
				<select class="in" id="lc" bind:value={form.locale}>
					<option value="">Not set</option>
					{#each locales as l (l.tag)}<option value={l.tag}>{l.name} · {l.tag}</option>{/each}
				</select>
			</div>
			<div>
				<label class="lbl" for="tz">Time zone</label>
				<select class="in" id="tz" bind:value={form.zoneinfo}>
					<option value="">Not set</option>
					{#each zones as z (z)}<option value={z}>{z}</option>{/each}
				</select>
				{#if form.zoneinfo !== browserZone}
					<p class="hint"><button class="link-btn" type="button" onclick={() => (form.zoneinfo = browserZone)}>Use this device's: {browserZone}</button></p>
				{/if}
			</div>
		</div>
	</section>

	<div class="actions">
		<button class="btn alt" type="button" onclick={discard} disabled={!dirty || busy}>Discard changes</button>
		<button class="btn" type="submit" disabled={!dirty || busy}>Save</button>
	</div>
</form>


<style>
	.stack {
		display: flex;
		flex-direction: column;
		gap: 20px;
	}
	.stack > p {
		margin: 0;
	}
	.about {
		display: flex;
		gap: 24px;
		flex-wrap: wrap;
		align-items: flex-start;
		margin-top: 18px;
	}
	.avatar {
		width: 88px;
		height: 88px;
		border-radius: 50%;
		background: var(--tile);
		display: grid;
		place-items: center;
		font: 600 32px Figtree, system-ui, sans-serif;
		color: var(--accent);
		object-fit: cover;
	}
	.fields {
		flex: 1 1 320px;
		display: grid;
		grid-template-columns: repeat(2, minmax(0, 1fr));
		gap: 18px;
	}
	.wide {
		grid-column: 1 / -1;
	}
	.intro {
		margin: 0 0 18px;
	}
	.mask {
		display: flex;
		align-items: center;
		gap: 10px;
		height: 42px;
		padding: 0 6px 0 12px;
		border: 1px solid var(--line);
		border-radius: 6px;
		background: var(--field);
		box-sizing: border-box;
	}
	.mask span {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.mask .none {
		color: var(--mute);
	}
	.email-actions {
		display: flex;
		align-items: center;
		gap: 12px;
		margin-top: 10px;
		flex-wrap: wrap;
		font-size: 14px;
	}
	.badge.ok {
		color: var(--ok);
	}
	.pending {
		margin-top: 12px;
	}
	.pending .email-actions {
		margin-top: 6px;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
	}
	.email-edit {
		margin-top: 14px;
	}
	@media (max-width: 760px) {
		.fields {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
