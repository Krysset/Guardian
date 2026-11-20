<!-- AC1 Profile. Part 1 of 0.4 builds "About you" and the username (a protected change, so it exercises the
     "Confirm it's you" dialog); the email, locale and time zone follow in part 2. -->
<script lang="ts">
	import { refreshAll } from '$app/navigation';
	import { api, ApiError, type Schema } from '#lib/api/client.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	type Fields = Required<Pick<Schema<'ProfileUpdate'>, 'username' | 'display_name' | 'given_name' | 'family_name' | 'picture_url'>>;

	function fromAccount(me: Schema<'Account'>): Fields {
		return {
			username: me.username,
			display_name: me.display_name ?? '',
			given_name: me.given_name ?? '',
			family_name: me.family_name ?? '',
			picture_url: me.picture_url ?? ''
		};
	}

	// The form starts from the account and stays as edited until saved or discarded.
	// svelte-ignore state_referenced_locally
	let saved = $state(fromAccount(data.me));
	// svelte-ignore state_referenced_locally
	let form = $state({ ...saved });
	let error = $state('');
	let fieldError = $state<Partial<Record<keyof Fields, string>>>({});
	let done = $state(false);
	let busy = $state(false);

	const changes = $derived(
		Object.fromEntries(Object.entries(form).filter(([k, v]) => v.trim() !== saved[k as keyof Fields])) as Partial<Fields>
	);
	const dirty = $derived(Object.keys(changes).length > 0);
	const initial = $derived((form.display_name || form.username || '?').trim().charAt(0).toUpperCase());

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
			const me = await api.patch('/me', { body, reason: 'change your username' });
			saved = fromAccount(me);
			form = { ...saved };
			done = true;
			await refreshAll();
		} catch (e) {
			if (e instanceof ApiError && e.code === 'cancelled') return;
			if (e instanceof ApiError && e.status === 409) fieldError = { username: e.message };
			else error = e instanceof ApiError ? e.message : 'Something went wrong. Try again.';
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
				<div class="avatar" aria-hidden="true">{initial}</div>
			{/if}
			<div class="fields">
				<div class="wide">
					<label class="lbl" for="pic">Picture address</label>
					<input
						class="in"
						id="pic"
						type="url"
						bind:value={form.picture_url}
						aria-invalid={fieldError.picture_url ? 'true' : undefined}
						aria-describedby="pic-hint"
					/>
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
		<h2 class="sec-h">Username</h2>
		<p class="hint intro">Changing it asks you to confirm it's you first.</p>
		<div class="grid2">
			<div>
				<label class="lbl" for="un">Username</label>
				<input
					class="in"
					id="un"
					bind:value={form.username}
					autocomplete="username"
					autocapitalize="none"
					spellcheck="false"
					aria-invalid={fieldError.username ? 'true' : undefined}
					aria-describedby="un-hint"
				/>
				{#if fieldError.username}<p class="err-t" id="un-hint">{fieldError.username}</p>
				{:else}<p class="hint" id="un-hint">3–64 letters, digits, dots, dashes or underscores.</p>{/if}
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
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
	}
	@media (max-width: 760px) {
		.fields {
			grid-template-columns: minmax(0, 1fr);
		}
	}
</style>
