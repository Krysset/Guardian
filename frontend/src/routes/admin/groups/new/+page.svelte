<!-- AD6 New group: the display name, the key (suggested from the name, checked as typed; it never changes), an optional owner group, and "Is
     this group for one app only?" with neither answer chosen; Yes asks for the app. -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import { messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();

	let key = $state('');
	let displayName = $state('');
	let description = $state('');
	let owner = $state('');
	let oneApp = $state<'' | 'yes' | 'no'>('');
	let app = $state('');
	let errors = $state<{ key?: string; name?: string; oneApp?: string; app?: string; form?: string }>({});
	let busy = $state(false);

	// The key follows the display name ("Test group" → "test-group") until it is typed in by hand; clearing it
	// makes it follow again.
	let keyEdited = false;
	function suggestKey(name: string): string {
		return name
			.normalize('NFD')
			.replace(/[̀-ͯ]/g, '')
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, '-')
			.replace(/^-+/, '')
			.slice(0, 63)
			.replace(/-+$/, '');
	}
	function nameTyped() {
		if (!keyEdited) key = suggestKey(displayName);
	}

	const keyOk = $derived(/^[a-z0-9][a-z0-9._-]{1,62}$/.test(key));
	const taken = $derived(data.groups.some((g) => g.key === key));
	// Any app may be chosen, enabled or not; an app may have several single-app groups.
	const apps = $derived([...data.apps].sort((a, b) => a.pretty_name.localeCompare(b.pretty_name)));

	async function create(event: SubmitEvent) {
		event.preventDefault();
		const e: typeof errors = {};
		if (!keyOk) e.key = 'Use 2–63 lowercase letters, digits, dots, dashes or underscores, starting with a letter or digit.';
		else if (taken) e.key = 'A group already has that key.';
		if (!displayName.trim()) e.name = 'Give the group a name people will see.';
		if (!oneApp) e.oneApp = 'Choose Yes or No.';
		else if (oneApp === 'yes' && !app) e.app = 'Choose the app.';
		errors = e;
		if (Object.keys(e).length) return;
		busy = true;
		try {
			const g = await api.post('/groups', {
				body: {
					key,
					display_name: displayName.trim(),
					...(description.trim() ? { description: description.trim() } : {}),
					...(owner ? { owner_group_id: owner } : {}),
					...(oneApp === 'yes' ? { bound_app_id: app } : {})
				}
			});
			await refreshAll();
			await goto(`/admin/groups/${g.id}`);
		} catch (err) {
			errors = err instanceof ApiError && err.status === 409 ? { key: err.message } : { form: messageOf(err) };
		} finally {
			busy = false;
		}
	}
</script>

<svelte:head><title>New group · Guardian</title></svelte:head>

<div class="ph"><p class="crumb"><a href="/admin/groups">Groups</a> / New</p><h1>New group</h1></div>

<form class="card" onsubmit={create} novalidate>
	<h2 class="sec-h">Group</h2>
	<div class="grid2 fields">
		<div>
			<label class="lbl" for="nn">Display name</label>
			<input class="in" id="nn" maxlength="128" bind:value={displayName} oninput={nameTyped} aria-invalid={errors.name ? 'true' : undefined} />
			{#if errors.name}<p class="err-t">{errors.name}</p>{/if}
		</div>
		<div>
			<label class="lbl" for="nk">Key</label>
			<input class="in" id="nk" bind:value={key} oninput={() => (keyEdited = key !== '')} autocomplete="off" autocapitalize="none" spellcheck="false" aria-invalid={errors.key ? 'true' : undefined} aria-describedby="nk-rule nk-hint" />
			{#if errors.key}<p class="err-t" id="nk-rule">{errors.key}</p>
			{:else}<p class="hint rule" id="nk-rule" class:ok={key && keyOk && !taken} class:bad={key && (!keyOk || taken)}>
					{key && taken ? 'A group already has that key.' : 'Lowercase letters, digits, dots, dashes and underscores.'}
				</p>{/if}
			<p class="hint" id="nk-hint"><strong>Never changes.</strong> Used as an identifier for apps.</p>
		</div>
		<div>
			<label class="lbl" for="nd">Description</label>
			<input class="in" id="nd" maxlength="1024" bind:value={description} placeholder="Optional" />
		</div>
		<div>
			<label class="lbl" for="no">Owner group <span class="optional">(optional)</span></label>
			<select class="in" id="no" bind:value={owner}>
				<option value="">None: only administrators</option>
				{#each data.groups as g (g.id)}<option value={g.id}>{g.display_name}</option>{/each}
			</select>
			<p class="hint">Its members can add and remove members of this group.</p>
		</div>
	</div>

	<fieldset class="one-app" aria-describedby={errors.oneApp ? 'oa-err' : undefined}>
		<legend class="lbl">Is this group for one app only?</legend>
		<div class="grid2">
			<label class="radio"><input type="radio" name="one" value="yes" bind:group={oneApp} /><span><strong>Yes</strong><span class="hint block">It is bound to that app for good and can't be linked to any other.</span></span></label>
			<label class="radio"><input type="radio" name="one" value="no" bind:group={oneApp} /><span><strong>No</strong><span class="hint block">It can be linked to any number of apps.</span></span></label>
		</div>
		{#if errors.oneApp}<p class="err-t" id="oa-err">{errors.oneApp}</p>{/if}
		{#if oneApp === 'yes'}
			<div class="which">
				<label class="lbl" for="na">Which app?</label>
				<select class="in" id="na" bind:value={app} aria-invalid={errors.app ? 'true' : undefined}>
					<option value="">Choose an app</option>
					{#each apps as a (a.id)}<option value={a.id}>{a.pretty_name}</option>{/each}
				</select>
				{#if errors.app}<p class="err-t">{errors.app}</p>{:else}<p class="hint">The group is linked to it, so its members can sign in to it.</p>{/if}
			</div>
		{/if}
	</fieldset>

	{#if errors.form}<p class="err-msg msg" role="alert">{errors.form}</p>{/if}
	<div class="actions"><a class="btn alt" href="/admin/groups">Cancel</a><button class="btn" type="submit" disabled={busy}>Create</button></div>
</form>

<style>
	.fields {
		margin-top: 14px;
	}
	.optional {
		color: var(--mute);
		font-weight: 400;
	}
	.rule.ok {
		color: var(--ok);
	}
	.rule.bad {
		color: var(--danger);
	}
	.one-app {
		border: 0;
		padding: 0;
		margin: 22px 0 0;
	}
	.radio {
		display: flex;
		gap: 12px;
		align-items: flex-start;
		padding: 14px 16px;
		border: 1px solid var(--line);
		border-radius: 8px;
		cursor: pointer;
	}
	.radio:has(input:checked) {
		border-color: var(--accent);
		background: var(--sel);
	}
	.radio input {
		margin-top: 4px;
		accent-color: var(--accent);
	}
	.radio strong {
		font-weight: 600;
	}
	.block {
		display: block;
	}
	.which {
		margin-top: 16px;
		max-width: 420px;
	}
	.msg {
		margin: 16px 0 0;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
		margin-top: 20px;
	}
</style>
