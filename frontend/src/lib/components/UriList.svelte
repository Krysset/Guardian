<!-- A list of URIs (redirect URIs, sign-out redirect URIs) with Remove on each and a field to add one. -->
<script lang="ts">
	let {
		id,
		label,
		uris = $bindable([]),
		hint = '',
		required = false
	}: { id: string; label: string; uris?: string[]; hint?: string; required?: boolean } = $props();

	let draft = $state('');
	let error = $state('');

	function add() {
		const uri = draft.trim();
		error = '';
		if (!uri) return;
		try {
			const u = new URL(uri);
			if (u.protocol !== 'https:' && !(u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)) && !/^[a-z][a-z0-9.+-]*:$/.test(u.protocol)) {
				throw new Error();
			}
			if (u.hash) {
				error = 'A redirect URI cannot have a #fragment.';
				return;
			}
		} catch {
			error = 'Enter a full address, such as https://app.example.com/callback.';
			return;
		}
		if (uris.includes(uri)) {
			error = 'That address is already in the list.';
			return;
		}
		uris = [...uris, uri];
		draft = '';
	}
</script>

<div>
	<span class="lbl" id="{id}-l">{label}</span>
	<ul class="uris" aria-labelledby="{id}-l">
		{#each uris as uri (uri)}
			<li class="uri">
				<code>{uri}</code>
				<button class="btn alt sm" type="button" aria-label="Remove {uri}" disabled={required && uris.length === 1} onclick={() => (uris = uris.filter((u) => u !== uri))}>Remove</button>
			</li>
		{/each}
	</ul>
	<div class="add">
		<input
			class="in"
			id="{id}-new"
			aria-label="New {label.toLowerCase().replace(/s$/, '')}"
			bind:value={draft}
			placeholder="https://…"
			autocomplete="off"
			spellcheck="false"
			aria-invalid={error ? 'true' : undefined}
			onkeydown={(e) => {
				if (e.key === 'Enter') {
					e.preventDefault();
					add();
				}
			}}
		/>
		<button class="btn alt" type="button" onclick={add}>Add</button>
	</div>
	{#if error}<p class="err-t" role="alert">{error}</p>{:else if hint}<p class="hint">{hint}</p>{/if}
</div>

<style>
	.uris {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 8px;
	}
	.uri {
		display: flex;
		align-items: center;
		gap: 8px;
		min-height: 42px;
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
	.add {
		display: flex;
		gap: 8px;
		margin-top: 8px;
	}
</style>
