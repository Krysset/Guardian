<!-- A password input with a Show button. -->
<script lang="ts">
	import Icon from './Icon.svelte';

	let {
		id,
		label,
		value = $bindable(''),
		autocomplete = 'new-password',
		error = ''
	}: { id: string; label: string; value?: string; autocomplete?: AutoFill; error?: string } = $props();
	let show = $state(false);
</script>

<div>
	<label class="lbl" for={id}>{label}</label>
	<div class="pw">
		<input
			class="in"
			{id}
			type={show ? 'text' : 'password'}
			bind:value
			{autocomplete}
			aria-invalid={error ? 'true' : undefined}
			aria-describedby={error ? `${id}-err` : undefined}
		/>
		<button class="btn alt sm" type="button" aria-label={show ? 'Hide password' : 'Show password'} aria-pressed={show} onclick={() => (show = !show)}
			><Icon name="eye" /></button
		>
	</div>
	{#if error}<p class="err-t" id="{id}-err">{error}</p>{/if}
</div>

<style>
	.pw {
		display: flex;
		align-items: center;
		gap: 6px;
		height: 42px;
		padding-right: 6px;
		border: 1px solid var(--line);
		border-radius: 6px;
		background: var(--field);
		box-sizing: border-box;
	}
	.pw:focus-within {
		border-color: var(--accent);
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 25%, transparent);
	}
	.pw .in {
		border: 0;
		height: 40px;
		background: transparent;
		box-shadow: none;
	}
</style>
