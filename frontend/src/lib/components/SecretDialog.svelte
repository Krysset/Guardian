<!-- AD10 The secret, shown once: after registering an app with a secret, or rotating it. Done turns on once
     the secret was copied or "I have stored it" is ticked; Escape does not close it. -->
<script lang="ts">
	import { formatWhen } from '#lib/format.ts';
	import CopyField from './CopyField.svelte';

	let {
		appName,
		secret,
		oldUntil = null,
		done
	}: { appName: string; secret: string; oldUntil?: string | null; done: () => void } = $props();

	let dialog: HTMLDialogElement | undefined = $state();
	let copied = $state(false);
	let stored = $state(false);

	$effect(() => {
		if (dialog && !dialog.open) dialog.showModal();
	});
</script>

<dialog bind:this={dialog} aria-labelledby="secret-h" oncancel={(e) => e.preventDefault()}>
	<h2 id="secret-h">{appName}'s new secret</h2>
	<p class="lead">This is the only time it is shown. Store it now.</p>
	<CopyField label="Client secret" value={secret} primary oncopy={() => (copied = true)} />
	{#if oldUntil}
		<p class="note">The old secret keeps working until <strong>{formatWhen(oldUntil).toLowerCase()}</strong>.</p>
	{/if}
	<label class="check"><input type="checkbox" bind:checked={stored} /> I have stored it</label>
	<div class="actions"><button class="btn" type="button" disabled={!copied && !stored} onclick={done}>Done</button></div>
	<p class="hint">Done turns on after Copy, or once the box is ticked.</p>
</dialog>

<style>
	dialog {
		width: min(520px, calc(100% - 32px));
		box-sizing: border-box;
		margin: 120px auto auto;
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
	.lead {
		margin: 0 0 18px;
		color: var(--warn);
		font-weight: 600;
	}
	.note {
		margin: 16px 0 0;
	}
	.check {
		display: flex;
		gap: 10px;
		align-items: center;
		margin-top: 16px;
		font-size: 14px;
	}
	.check input {
		accent-color: var(--accent);
		width: 18px;
		height: 18px;
	}
	.actions {
		display: flex;
		justify-content: flex-end;
		margin-top: 18px;
	}
</style>
