<!-- AD5 Group: the key (never changes) and binding (permanent), names and owner group, members (with account
     search), binding to one app, and delete (type the key). Built-in groups are read-only. Linking to apps is
     done on the app's page. -->
<script lang="ts">
	import { goto, refreshAll } from '$app/navigation';
	import { api, ApiError } from '#lib/api/client.ts';
	import { askConfirm } from '#lib/confirm.svelte.ts';
	import CopyField from '#lib/components/CopyField.svelte';
	import GroupMembers from '#lib/components/GroupMembers.svelte';
	import GroupRequests from '#lib/components/GroupRequests.svelte';
	import { messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const group = $derived(data.group);
	const appName = $derived(new Map(data.apps.map((a) => [a.id, a.pretty_name])));
	const linked = $derived(group.app_ids.map((id) => ({ id, name: appName.get(id) ?? 'An app' })));
	const boundName = $derived(group.bound_app_id ? appName.get(group.bound_app_id) : undefined);
	// Owner choices: any other group (a group cannot own itself).
	const owners = $derived(data.groups.filter((g) => g.id !== group.id));

	function formOf(g: typeof data.group) {
		return {
			display_name: g.display_name,
			description: g.description,
			owner: g.owner_group_id ?? '',
			hidden: g.hidden,
			requestable: g.requestable,
			join_by_default: g.join_by_default
		};
	}
	// svelte-ignore state_referenced_locally
	let form = $state(formOf(data.group));
	// svelte-ignore state_referenced_locally
	let shownId = data.group.id;
	$effect(() => {
		if (data.group.id !== shownId) {
			shownId = data.group.id;
			form = formOf(data.group);
		}
	});
	const dirty = $derived(
		form.display_name.trim() !== group.display_name ||
			form.description.trim() !== group.description ||
			form.owner !== (group.owner_group_id ?? '') ||
			form.hidden !== group.hidden ||
			form.requestable !== group.requestable ||
			form.join_by_default !== group.join_by_default
	);

	let note = $state<{ section: string; ok: boolean; text: string } | null>(null);
	let bindApp = $state('');

	async function save(event: SubmitEvent) {
		event.preventDefault();
		note = null;
		if (!form.display_name.trim()) return (note = { section: 'details', ok: false, text: 'The display name cannot be empty.' });
		try {
			await api.patch('/groups/{group}', { path: { group: group.id }, body: {
					display_name: form.display_name.trim(),
					description: form.description.trim(),
					owner_group_id: form.owner,
					hidden: form.hidden,
					requestable: form.requestable,
					join_by_default: form.join_by_default
				}
			});
			note = { section: 'details', ok: true, text: 'Saved.' };
			await refreshAll();
		} catch (e) {
			note = { section: 'details', ok: false, text: messageOf(e) };
		}
	}

	async function bind() {
		note = null;
		const name = appName.get(bindApp);
		if (!bindApp || !name) return;
		if (!(await askConfirm({ title: `Bind ${group.display_name} to ${name} for good?`, message: `It can then only ever be linked to ${name}. A binding cannot be undone.`, confirm: 'Bind for good', danger: true }))) return;
		try {
			await api.post('/groups/{group}/bind', { path: { group: group.id }, body: { app_id: bindApp } });
			bindApp = '';
			await refreshAll();
		} catch (e) {
			note = { section: 'bind', ok: false, text: messageOf(e) };
		}
	}

	async function remove() {
		note = null;
		const affects = [
			group.member_count ? `${group.member_count} ${group.member_count === 1 ? 'member loses' : 'members lose'} it` : '',
			linked.length ? `${linked.map((a) => a.name).join(', ')} ${linked.length === 1 ? 'stops' : 'stop'} seeing it` : ''
		].filter(Boolean);
		if (!(await askConfirm({ title: `Delete ${group.display_name}?`, message: affects.length ? `${affects.join(', and ')}. This cannot be undone.` : 'This cannot be undone.', confirm: 'Delete', danger: true, typeToConfirm: group.key }))) return;
		try {
			await api.delete('/groups/{group}', { path: { group: group.id } });
			await refreshAll();
			await goto('/admin/groups');
		} catch (e) {
			if (!(e instanceof ApiError && e.code === 'cancelled')) note = { section: 'delete', ok: false, text: messageOf(e) };
		}
	}
</script>

<svelte:head><title>{group.display_name} · Guardian</title></svelte:head>

{#snippet message(section: string)}
	{#if note?.section === section}<p class={note.ok ? 'ok-msg msg' : 'err-msg msg'} role={note.ok ? 'status' : 'alert'}>{note.text}</p>{/if}
{/snippet}

<div class="ph">
	<p class="crumb"><a href="/admin/groups">Groups</a> / {group.display_name}</p>
	<h1>{group.display_name}</h1>
	{#if group.is_system || group.single_app}
		<div class="badges">
			{#if group.is_system}<span class="badge mute">built-in</span>{/if}
			{#if group.single_app}<span class="badge hl">{boundName ? `bound to ${boundName}` : 'bound to a deleted app'}</span>{/if}
		</div>
	{/if}
</div>

{#if group.is_system}
	<section class="card">
		<h2 class="sec-h">Details</h2>
		<div class="grid2 fields">
			<div><CopyField label="Key" value={group.key} /></div>
			<div><span class="lbl">Display name</span><p class="value">{group.display_name}</p></div>
		</div>
		<p class="note">{group.display_name} is built in. Its key, name and owner can't be changed and it can't be deleted, because Guardian uses it to decide who may open the admin area.</p>
	</section>
{:else}
	<form class="card" onsubmit={save} novalidate>
		<h2 class="sec-h">Details</h2>
		<div class="grid2 fields">
			<div><CopyField label="Key" value={group.key} /><p class="hint">Never changes. Apps see this.</p></div>
			{#if group.single_app}
				<div>
					<span class="lbl">Bound to</span>
					<p class="value bound">{boundName ?? 'A deleted app'}</p>
					<p class="hint">{boundName ? `Permanent. It can only be linked to ${boundName}.` : 'Its app was deleted, so it can never be linked again.'}</p>
				</div>
			{/if}
			<div><label class="lbl" for="gdn">Display name</label><input class="in" id="gdn" maxlength="128" bind:value={form.display_name} /></div>
			<div>
				<label class="lbl" for="gow">Owner group</label>
				<select class="in" id="gow" bind:value={form.owner}>
					<option value="">None: only administrators</option>
					{#each owners as g (g.id)}<option value={g.id}>{g.display_name}</option>{/each}
				</select>
				<p class="hint">Its members can add and remove members here.</p>
			</div>
			<div class="wide"><label class="lbl" for="gde">Description</label><input class="in" id="gde" maxlength="1024" bind:value={form.description} /></div>
		</div>
		<div class="switches">
			<label class="switch">
				<span><strong>New accounts join</strong><span class="hint block">Every account created from now on, by sign-up or by an administrator.</span></span>
				<input type="checkbox" bind:checked={form.join_by_default} />
			</label>
			<!-- A hidden group cannot be asked for: asking would show it to everyone. While one is on, the other is
			     off and says why. -->
			<label class="switch" class:off={form.hidden}>
				<span>
					<strong>People can ask to join</strong>
					<span class="hint block">From their groups page, or when {group.display_name}'s apps refuse them. {form.owner ? 'The owners' : 'Administrators'} decide.</span>
					{#if form.hidden}<span class="why block">Not possible while the group is hidden: asking would show it to everyone. Turn off "Hidden from its members" first.</span>{/if}
				</span>
				<input type="checkbox" bind:checked={form.requestable} disabled={form.hidden} />
			</label>
			<label class="switch" class:off={form.requestable}>
				<span>
					<strong>Hidden from its members</strong>
					<span class="hint block">Left out of their own groups page. Apps still see it in sign-ins, so it isn't secret.</span>
					{#if form.requestable}<span class="why block">Not possible while people can ask to join: the list of groups to ask for shows it. Turn off "People can ask to join" first.</span>{/if}
				</span>
				<input type="checkbox" bind:checked={form.hidden} disabled={form.requestable} />
			</label>
		</div>
		{@render message('details')}
		<div class="foot">
			<span class="hint">
				Linked apps:
				{#if linked.length}{#each linked as a, i (a.id)}{i ? ', ' : ''}<a href="/admin/apps/{a.id}">{a.name}</a>{/each}{:else}none{/if}.
				Linking is done on the app's page.
			</span>
			<button class="btn" type="submit" disabled={!dirty}>Save</button>
		</div>
	</form>
{/if}

<GroupRequests groupId={group.id} groupName={group.display_name} requests={data.requests} />

<GroupMembers groupId={group.id} groupName={group.display_name} members={data.members} search accountLinks />

<section class="card">
	<div class="row">
		<span class="grow">
			<strong>Copy this group</strong>
			<span class="hint block">A new, separate group that starts with the same members and expiry dates. For example to replace an app, or to start a group that will grow apart.</span>
		</span>
		<a class="btn alt" href="/admin/groups/new?copy={group.id}">Copy</a>
	</div>
</section>

{#if !group.is_system}
	<section class="card danger-card">
		<h2 class="sec-h">Other actions</h2>
		<div class="rows">
			{#if !group.single_app}
				<div class="row">
					<span class="grow">
						<strong>Bind to one app</strong>
						<span class="hint block">
							{linked.length > 1 ? 'Only possible while the group is linked to at most one app.' : 'Permanent: it can then never be linked to another app.'}
						</span>
						{#if linked.length <= 1}
							<label class="visually-hidden" for="bind">App to bind to</label>
							<select class="in bind" id="bind" bind:value={bindApp}>
								<option value="">Choose an app</option>
								{#each data.apps.filter((a) => !linked.length || a.id === linked[0].id) as a (a.id)}<option value={a.id}>{a.pretty_name}</option>{/each}
							</select>
						{/if}
					</span>
					<button class="btn alt" type="button" disabled={!bindApp || linked.length > 1} onclick={bind}>Bind</button>
				</div>
				{@render message('bind')}
			{/if}
			<div class="row">
				<span><strong>Delete {group.display_name}</strong><span class="hint block">You type the key to confirm.</span></span>
				<button class="btn danger" type="button" onclick={remove}>Delete</button>
			</div>
			{@render message('delete')}
		</div>
	</section>
{/if}

<style>
	.badges {
		display: flex;
		gap: 8px;
		margin-top: 8px;
	}
	.badge.hl {
		color: var(--hl);
	}
	.badge.mute {
		color: var(--mute);
	}
	.fields,
	.rows {
		margin-top: 14px;
	}
	.wide {
		grid-column: 1 / -1;
	}
	.value {
		margin: 0;
		height: 42px;
		display: flex;
		align-items: center;
		padding: 0 12px;
		border: 1px solid var(--line);
		border-radius: 6px;
		box-sizing: border-box;
	}
	.value.bound {
		background: var(--tile);
	}
	.note {
		margin: 16px 0 0;
	}
	.msg {
		margin: 14px 0 0;
	}
	.foot {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: 12px;
		margin-top: 20px;
		flex-wrap: wrap;
	}
	.foot .hint {
		margin: 0;
	}
	.danger-card {
		border-color: var(--danger);
	}
	.grow {
		flex: 1 1 320px;
	}
	.block {
		display: block;
		margin: 0;
	}
	.bind {
		margin-top: 10px;
		max-width: 320px;
	}
	.switches {
		display: flex;
		flex-direction: column;
		gap: 14px;
		margin-top: 20px;
	}
	.switch {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 18px;
		cursor: pointer;
	}
	.switch strong {
		font-weight: 600;
	}
	.switch.off {
		cursor: not-allowed;
	}
	.switch.off strong,
	.switch.off .hint {
		opacity: 0.5;
	}
	.switch input:disabled {
		cursor: not-allowed;
		opacity: 0.35;
	}
	.why {
		margin-top: 4px;
		font-size: 13px;
		color: var(--warn);
	}
	.switch input {
		width: 20px;
		height: 20px;
		accent-color: var(--accent);
		flex: none;
	}
</style>
