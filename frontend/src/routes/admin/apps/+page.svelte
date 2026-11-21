<!-- AD7 Apps: every app with its type, who may sign in, linked groups and whether it is enabled. An app admin
     sees only their own apps, and no New app. -->
<script lang="ts">
	import AppLogo from '#lib/components/AppLogo.svelte';
	import Icon from '#lib/components/Icon.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const isAdmin = $derived(data.me.is_admin);
	// An app admin knows only the groups they own; the others are counted.
	function linkedNames(ids: string[]): string {
		const names = ids.map((id) => groupName.get(id)).filter(Boolean);
		const others = ids.length - names.length;
		if (others) names.push(others === 1 ? '1 other group' : `${others} other groups`);
		return names.join(', ') || '—';
	}
	const groupName = $derived(new Map(data.groups.map((g) => [g.id, g.display_name])));
	const apps = $derived([...data.apps].sort((a, b) => a.pretty_name.localeCompare(b.pretty_name)));
</script>

<svelte:head><title>Apps · Guardian</title></svelte:head>

<div class="head">
	{#if isAdmin}
		<div class="ph"><h1>Apps</h1><p>Apps that sign people in with Guardian.</p></div>
		<a class="btn" href="/admin/apps/new"><Icon name="plus" />New app</a>
	{:else}
		<div class="ph"><h1>Your apps</h1><p>The apps you are an admin of, through one of your groups.</p></div>
	{/if}
</div>

<section class="card">
	{#if apps.length}
		<div class="scroll">
			<table class="tbl">
				<thead><tr><th>App</th><th>Type</th><th>Who can sign in</th><th>Linked groups</th><th>Status</th></tr></thead>
				<tbody>
					{#each apps as a (a.id)}
						<tr>
							<td><span class="app"><AppLogo name={a.pretty_name} logo={a.logo_url} /><a href="/admin/apps/{a.id}">{a.pretty_name}</a></span></td>
							<td>{a.client_type === 'confidential' ? 'With a secret' : 'Without a secret'}</td>
							<td>{a.access_rule === 'anyone' ? 'Anyone with an account' : 'Linked groups only'}</td>
							<td>{linkedNames(a.group_ids)}</td>
							<td>{#if a.enabled}<span class="badge ok">Enabled</span>{:else}<span class="badge mute">Disabled</span>{/if}</td>
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{:else}
		<p class="empty">{isAdmin ? 'No apps yet. Register the first one with New app.' : 'You are not an admin of any app.'}</p>
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
	.app {
		display: flex;
		align-items: center;
		gap: 10px;
	}
	.tbl td {
		vertical-align: middle;
	}
	.badge.ok {
		color: var(--ok);
	}
	.badge.mute {
		color: var(--mute);
	}
	.empty {
		margin: 0;
		padding: 24px;
		text-align: center;
		border: 1px dashed var(--line);
		border-radius: 8px;
		color: var(--mute);
	}
</style>
