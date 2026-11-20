<!-- AC5 Groups: the groups the user is in, and the groups they manage as an owner (each opens AC6). Display
     names only: users never need group keys. -->
<script lang="ts">
	import { formatDate } from '#lib/format.ts';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const memberOf = $derived(data.groups.member_of);
	const manages = $derived(data.groups.manages);
</script>

<svelte:head><title>Groups · Guardian</title></svelte:head>

<div class="ph"><h1>Groups</h1><p>Groups decide which apps you can use and what you can do in them.</p></div>

{#if !memberOf.length && !manages.length}
	<section class="card">
		<p class="empty">You are not in any groups yet. An administrator or group owner can add you.</p>
	</section>
{:else}
	{#if memberOf.length}
		<section class="card">
			<h2 class="sec-h">Groups you're in</h2>
			<div class="scroll">
				<table class="tbl">
					<thead><tr><th>Group</th><th>Description</th><th>Expires</th></tr></thead>
					<tbody>
						{#each memberOf as g (g.id)}
							<tr><td><strong>{g.display_name}</strong></td><td>{g.description}</td><td>{g.expires_at ? formatDate(g.expires_at) : 'Never'}</td></tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}

	{#if manages.length}
		<section class="card">
			<h2 class="sec-h">Groups you manage</h2>
			<p class="hint intro">You can add and remove members of these.</p>
			<div class="scroll">
				<table class="tbl">
					<thead><tr><th>Group</th><th class="num">Members</th><th>Linked apps</th><th><span class="visually-hidden">Open</span></th></tr></thead>
					<tbody>
						{#each manages as g (g.id)}
							<tr>
								<td><strong>{g.display_name}</strong></td>
								<td class="num">{g.member_count}</td>
								<td>{g.apps.length ? g.apps.join(', ') : 'None'}</td>
								<td class="end"><a class="btn alt sm" href="/account/groups/{g.id}" aria-label="Open {g.display_name}">Open</a></td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}
{/if}

<style>
	.scroll {
		margin-top: 14px;
	}
	.intro {
		margin: 0 0 4px;
	}
	td strong {
		font-weight: 600;
	}
	.end {
		text-align: right;
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
