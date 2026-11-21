<!-- A value to copy into another system's configuration: a client id, a discovery URL, a group key. -->
<script lang="ts">
	let { label, value, oncopy, primary = false }: { label?: string; value: string; oncopy?: () => void; primary?: boolean } = $props();
	let copied = $state(false);

	async function copy() {
		try {
			await navigator.clipboard.writeText(value);
			copied = true;
			oncopy?.();
			setTimeout(() => (copied = false), 2000);
		} catch {
			copied = false;
		}
	}
</script>

<div>
	{#if label}<span class="lbl">{label}</span>{/if}
	<div class="copy">
		<code>{value}</code>
		<button class={primary ? 'btn sm' : 'btn alt sm'} type="button" onclick={copy} aria-label={label ? `Copy ${label.toLowerCase()}` : 'Copy'}>{copied ? 'Copied' : 'Copy'}</button>
	</div>
</div>

<style>
	.copy {
		display: flex;
		align-items: center;
		gap: 8px;
		height: 42px;
		padding: 0 6px 0 12px;
		border: 1px solid var(--line);
		border-radius: 6px;
		background: var(--bg);
		box-sizing: border-box;
	}
	code {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
		font: 500 14px ui-monospace, Menlo, Consolas, monospace;
	}
</style>
