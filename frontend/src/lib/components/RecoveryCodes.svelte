<!-- The 10 recovery codes, shown once (as on S16): copy or download them, then type one back to prove they
     were saved. `finish` sends that code; it rejects with the API's error when the code is not one of them. -->
<script lang="ts">
	import { messageOf } from '#lib/format.ts';

	let {
		codes,
		finish,
		cancel
	}: { codes: string[]; finish: (code: string) => Promise<void>; cancel: () => void } = $props();

	let answer = $state('');
	let error = $state('');
	let copied = $state(false);
	let busy = $state(false);

	const text = $derived(codes.join('\n') + '\n');
	const download = $derived('data:text/plain;charset=utf-8,' + encodeURIComponent(text));

	async function copy() {
		try {
			await navigator.clipboard.writeText(text);
			copied = true;
		} catch {
			copied = false;
		}
	}

	async function submit(event: SubmitEvent) {
		event.preventDefault();
		if (!answer.trim()) {
			error = 'Type one of the codes above.';
			return;
		}
		busy = true;
		error = '';
		try {
			await finish(answer.trim());
		} catch (e) {
			error = messageOf(e);
		} finally {
			busy = false;
		}
	}
</script>

<div class="recovery">
	<p>If you lose your phone, each code gets you in once. <strong>This is the only time they're shown.</strong></p>
	<ul class="codes" aria-label="Recovery codes">
		{#each codes as code (code)}<li><code>{code}</code></li>{/each}
	</ul>
	<div class="tools">
		<button class="btn alt sm" type="button" onclick={copy}>{copied ? 'Copied' : 'Copy'}</button>
		<a class="btn alt sm" href={download} download="guardian-recovery-codes.txt">Download</a>
	</div>
	<form onsubmit={submit} novalidate>
		<label class="lbl" for="rc-answer">Type one of the codes to show you saved them</label>
		<div class="answer">
			<input
				class="in"
				id="rc-answer"
				bind:value={answer}
				autocomplete="off"
				autocapitalize="off"
				spellcheck="false"
				maxlength="20"
				aria-invalid={error ? 'true' : undefined}
				aria-describedby={error ? 'rc-err' : undefined}
			/>
			<button class="btn" type="submit" disabled={busy}>Finish</button>
			<button class="btn alt" type="button" onclick={cancel}>Cancel</button>
		</div>
		{#if error}<p class="err-t" id="rc-err" role="alert">{error}</p>{/if}
	</form>
</div>

<style>
	.recovery {
		display: flex;
		flex-direction: column;
		gap: 14px;
	}
	p {
		margin: 0;
	}
	.codes {
		list-style: none;
		margin: 0;
		padding: 14px;
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
		gap: 8px 16px;
		border-radius: 8px;
		background: var(--field);
		border: 1px solid var(--line);
	}
	code {
		font: 500 15px ui-monospace, Menlo, Consolas, monospace;
		letter-spacing: 0.02em;
	}
	.tools,
	.answer {
		display: flex;
		gap: 10px;
		flex-wrap: wrap;
	}
	.answer .in {
		flex: 1 1 200px;
		max-width: 260px;
	}
</style>
