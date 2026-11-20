<!-- An app's logo, or the first letter of its name on a tile when it has none (or the image fails). -->
<script lang="ts">
	import { initial } from '#lib/format.ts';

	let { name, logo, size = 36 }: { name: string; logo?: string; size?: number } = $props();
	let failed = $state(false);
</script>

{#if logo && !failed}
	<img class="logo" src={logo} alt="" width={size} height={size} referrerpolicy="no-referrer" onerror={() => (failed = true)} />
{:else}
	<span class="logo tile" style:width="{size}px" style:height="{size}px" style:font-size="{Math.round(size * 0.42)}px" aria-hidden="true"
		>{initial(name)}</span
	>
{/if}

<style>
	.logo {
		flex: none;
		border-radius: 9px;
		object-fit: contain;
	}
	.tile {
		display: grid;
		place-items: center;
		background: var(--tile);
		color: var(--accent);
		font-weight: 600;
	}
</style>
