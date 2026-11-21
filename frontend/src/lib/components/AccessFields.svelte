<!-- Who may sign in to an app: the rule, and the linked groups as chips with "Link a group". Groups bound to
     another app cannot be picked. For an app admin, `groups` holds only the groups they own: the others that
     are linked are named from `linked` and cannot be unlinked here. -->
<script lang="ts">
	import type { Schema } from '#lib/api/client.ts';

	let {
		rule = $bindable(),
		groupIds = $bindable([]),
		groups,
		appId = '',
		appName = 'the app',
		linked = [],
		ownOnly = false
	}: {
		rule: 'groups' | 'anyone';
		groupIds?: string[];
		groups: Schema<'Group'>[];
		appId?: string;
		appName?: string;
		linked?: { id: string; display_name: string }[];
		ownOnly?: boolean;
	} = $props();

	let picking = $state('');
	const byId = $derived(new Map(groups.map((g) => [g.id, g])));
	const linkedName = $derived(new Map(linked.map((g) => [g.id, g.display_name])));
	// A single-app group may only be linked to its own app; one whose app was deleted, to none.
	const pickable = $derived(
		groups.filter((g) => !groupIds.includes(g.id) && !g.is_system && (!g.single_app || (g.bound_app_id && g.bound_app_id === appId)))
	);

	function link() {
		if (picking) groupIds = [...groupIds, picking];
		picking = '';
	}
</script>

<fieldset class="rule">
	<legend class="visually-hidden">Who may sign in</legend>
	<label class="radio"><input type="radio" name="rule" value="groups" bind:group={rule} /><span><strong>Members of linked groups</strong><span class="hint block">{groupIds.length ? 'Everyone else is refused at sign-in.' : 'Nobody can sign in until a group is linked.'}</span></span></label>
	<label class="radio"><input type="radio" name="rule" value="anyone" bind:group={rule} /><span><strong>Anyone with an account</strong><span class="hint block">Linked groups only decide what {appName} sees.</span></span></label>
</fieldset>

<span class="lbl" id="linked-l">Linked groups</span>
<div class="chips" aria-labelledby="linked-l">
	{#each groupIds as id (id)}
		{@const g = byId.get(id)}
		{@const label = g?.display_name ?? linkedName.get(id) ?? 'A group'}
		<span class="chip">
			{label}
			{#if g?.single_app}<span class="badge tiny">bound to {appName}</span>{/if}
			{#if g || !ownOnly}
				<button type="button" aria-label="Unlink {label}" onclick={() => (groupIds = groupIds.filter((x) => x !== id))}>✕</button>
			{:else}
				<span class="badge tiny" title="Only its owners or an administrator can unlink it">not yours</span>
			{/if}
		</span>
	{:else}
		<span class="hint none">None linked.</span>
	{/each}
</div>
<div class="pick">
	<label class="visually-hidden" for="link-group">Group to link</label>
	<select class="in" id="link-group" bind:value={picking}>
		<option value="">Choose a group to link</option>
		{#each pickable as g (g.id)}<option value={g.id}>{g.display_name}</option>{/each}
	</select>
	<button class="btn alt" type="button" disabled={!picking} onclick={link}>Link</button>
</div>
<p class="hint">{ownOnly ? 'You can link the groups you own. ' : ''}Groups bound to another app can't be picked.</p>

<style>
	.rule {
		border: 0;
		padding: 0;
		margin: 0 0 18px;
		display: grid;
		grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
		gap: 12px;
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
		margin: 0;
	}
	.chips {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
		align-items: center;
	}
	.chip {
		display: inline-flex;
		align-items: center;
		gap: 8px;
		padding: 4px 8px 4px 12px;
		border: 1px solid var(--line);
		border-radius: 99px;
		background: var(--bg);
		font-size: 14px;
	}
	.chip button {
		border: 0;
		background: none;
		color: var(--mute);
		cursor: pointer;
		padding: 0 4px;
		font: inherit;
	}
	.chip button:hover {
		color: var(--danger);
	}
	.badge.tiny {
		font-size: 11px;
		padding: 0 6px;
		color: var(--hl);
	}
	.none {
		margin: 0;
	}
	.pick {
		display: flex;
		gap: 8px;
		margin-top: 12px;
		max-width: 460px;
	}
</style>
