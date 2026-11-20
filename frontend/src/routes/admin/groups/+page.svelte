<!-- AD4 Groups: every group with its key, members, owner group and linked apps; filter by name or key. -->
<script lang="ts">
	import Icon from '#lib/components/Icon.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	let filter = $state('');

	const groupName = $derived(new Map(data.groups.map((g) => [g.id, g.display_name])));
	const appName = $derived(new Map(data.apps.map((a) => [a.id, a.pretty_name])));
	const shown = $derived.by(() => {
		const f = filter.trim().toLowerCase();
		return f ? data.groups.filter((g) => g.display_name.toLowerCase().includes(f) || g.key.includes(f)) : data.groups;
	});
	const apps = (ids: string[]) => ids.map((id) => appName.get(id)).filter(Boolean).join(', ') || '—';
</script>

<svelte:head><title>Groups · Guardian</title></svelte:head>

<div class="head">
	<div class="ph"><h1>Groups</h1><p>Groups decide who can sign in to which app, and what the app is told.</p></div>
	<a class="btn" href="/admin/groups/new"><Icon name="plus" />New group</a>
</div>

<section class="card">
	<div class="filter">
		<label class="lbl" for="gq">Filter</label>
		<input class="in" id="gq" type="search" bind:value={filter} placeholder="Name or key" autocomplete="off" />
	</div>
	{#if shown.length}
		<div class="scroll list">
			<table class="tbl">
				<thead><tr><th>Group</th><th>Key</th><th class="num">Members</th><th>Owner group</th><th>Linked apps</th></tr></thead>
				<tbody>
					{#each shown as g (g.id)}
						<tr>
							<td>
								<a href="/admin/groups/{g.id}">{g.display_name}</a>
								{#if g.is_system}<span class="badge small mute">built-in</span>{/if}
								{#if g.single_app}<span class="badge small hl">{g.bound_app_id && appName.get(g.bound_app_id) ? `bound to ${appName.get(g.bound_app_id)}` : 'bound to a deleted app'}</span>{/if}
							</td>
							<td><code>{g.key}</code></td>
							<td class="num">{g.member_count}</td>
							<td>{g.owner_group_id ? (groupName.get(g.owner_group_id) ?? '—') : '—'}</td>
							<td>{apps(g.app_ids)}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="empty">{filter ? 'No groups match.' : 'No groups yet.'}</p>
	{/if}
</section>

<style>
	.head {
		display: flex;
		justify-content: space-between;
		align-items: flex-end;
		gap: 16px;
		flex-wrap: wrap;
	}
	.filter {
		max-width: 360px;
	}
	.list {
		margin-top: 18px;
	}
	code {
		font: 500 13px ui-monospace, Menlo, Consolas, monospace;
	}
	.badge.small {
		font-size: 12px;
		padding: 0 8px;
		margin-left: 6px;
	}
	.badge.hl {
		color: var(--hl);
	}
	.badge.mute {
		color: var(--mute);
	}
	.empty {
		margin: 18px 0 0;
		padding: 24px;
		text-align: center;
		border: 1px dashed var(--line);
		border-radius: 8px;
		color: var(--mute);
	}
</style>
