<!-- The confirmation asked before something that cannot be undone (confirm.svelte.ts). -->
<script lang="ts">
	import { tick } from 'svelte';
	import { confirmation } from '#lib/confirm.svelte.ts';

	let dialog: HTMLDialogElement | undefined = $state();
	let cancelButton: HTMLButtonElement | undefined = $state();
	const pending = $derived(confirmation.pending);

	$effect(() => {
		if (pending && dialog && !dialog.open) {
			dialog.showModal();
			// The safe choice has the focus, so Enter does not confirm by accident.
			tick().then(() => cancelButton?.focus());
		} else if (!pending && dialog?.open) {
			dialog.close();
		}
	});
</script>

<dialog bind:this={dialog} aria-labelledby="confirm-h" oncancel={() => pending?.done(false)}>
	{#if pending}
		<h2 id="confirm-h">{pending.title}</h2>
		{#if pending.message}<p>{pending.message}</p>{/if}
		<div class="actions">
			<button bind:this={cancelButton} class="btn alt" type="button" onclick={() => pending.done(false)}>Cancel</button>
			<button class={pending.danger ? 'btn danger solid' : 'btn'} type="button" onclick={() => pending.done(true)}
				>{pending.confirm}</button
			>
		</div>
	{/if}
</dialog>

<style>
	dialog {
		width: min(440px, calc(100% - 32px));
		box-sizing: border-box;
		margin: 150px auto auto;
		background: var(--surface);
		color: var(--ink);
		border-radius: 12px;
		border: 1px solid var(--line);
		box-shadow: 0 30px 80px -20px rgba(0, 0, 0, 0.55);
		padding: 26px 28px;
	}
	dialog::backdrop {
		background: rgba(6, 18, 22, 0.45);
	}
	h2 {
		font: 600 20px/1.3 Figtree, system-ui, sans-serif;
		margin: 0 0 6px;
	}
	p {
		margin: 0;
		color: var(--mute);
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		gap: 12px;
		margin-top: 22px;
	}
</style>
