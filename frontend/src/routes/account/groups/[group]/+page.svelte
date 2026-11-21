<!-- AC6 Owned group: an owner adds members by exact username or email (no suggestions, so the only answers
     are "No user found" and "User added"), changes when a membership expires, and removes members. The linked
     apps are shown by name; only an administrator can change them. -->
<script lang="ts">
	import GroupMembers from '#lib/components/GroupMembers.svelte';
	import GroupRequests from '#lib/components/GroupRequests.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const group = $derived(data.group);
</script>

<svelte:head><title>{group.display_name} · Guardian</title></svelte:head>

<div class="ph">
	<p class="crumb"><a href="/account/groups">Groups</a> / {group.display_name}</p>
	<h1>{group.display_name}</h1>
	{#if group.description}<p>{group.description}</p>{/if}
</div>

<section class="card">
	<h2 class="sec-h">Linked apps</h2>
	<p class="hint intro">Members can sign in to these apps. Only an administrator can change them.</p>
	{#if group.apps.length}
		<div class="chips">{#each group.apps as name (name)}<span class="chip">{name}</span>{/each}</div>
	{:else}
		<p class="hint none">None yet.</p>
	{/if}
</section>

<GroupRequests groupId={group.id} groupName={group.display_name} requests={data.requests} />

<GroupMembers groupId={group.id} groupName={group.display_name} members={data.members} />

<style>
	.intro {
		margin: 0 0 18px;
	}
	.none {
		margin: 0;
	}
	.chips {
		display: flex;
		gap: 8px;
		flex-wrap: wrap;
	}
	.chip {
		display: inline-flex;
		padding: 4px 12px;
		border: 1px solid var(--line);
		border-radius: 99px;
		background: var(--bg);
		font-size: 14px;
	}
</style>
