<!-- The settings an app has besides its name and access: shown on AD8, and folded away on AD9. -->
<script lang="ts" module>
	export type AppSettingsValue = {
		description: string;
		logo_url: string;
		homepage_url: string;
		post_logout_redirect_uris: string[];
		backchannel_logout_uri: string;
		is_first_party: boolean;
		access_token_ttl_seconds: number;
		scopes: string[];
		require_mfa: boolean;
		signing_alg: 'RS256' | 'ES256';
	};

	export const ttlChoices: [number, string][] = [
		[60, '1 minute'],
		[300, '5 minutes (recommended)'],
		[900, '15 minutes'],
		[3600, '1 hour']
	];
</script>

<script lang="ts">
	import UriList from './UriList.svelte';

	let {
		value = $bindable(),
		scopes,
		appName = 'the app'
	}: { value: AppSettingsValue; scopes: { name: string; description: string }[]; appName?: string } = $props();

	const choices = $derived(ttlChoices.some(([s]) => s === value.access_token_ttl_seconds) ? ttlChoices : [...ttlChoices, [value.access_token_ttl_seconds, `${value.access_token_ttl_seconds} seconds`] as [number, string]]);

	function toggleScope(name: string, on: boolean) {
		value.scopes = on ? [...value.scopes, name] : value.scopes.filter((s) => s !== name);
	}
</script>

<div class="grid2">
	<div><label class="lbl" for="as-desc">Description</label><input class="in" id="as-desc" maxlength="1024" bind:value={value.description} placeholder="Optional" /><p class="hint">Shown on Home.</p></div>
	<div><label class="lbl" for="as-home">Homepage</label><input class="in" id="as-home" type="url" bind:value={value.homepage_url} placeholder="https://…" /><p class="hint">Where Home opens the app. Without one it is not on Home.</p></div>
	<div><label class="lbl" for="as-logo">Logo address</label><input class="in" id="as-logo" type="url" bind:value={value.logo_url} placeholder="https://…" /></div>
	<div>
		<label class="lbl" for="as-ttl">Token lifetime</label>
		<select class="in" id="as-ttl" bind:value={value.access_token_ttl_seconds}>
			{#each choices as [seconds, label] (seconds)}<option value={seconds}>{label}</option>{/each}
		</select>
		<p class="hint">Also how long {appName} may show outdated groups.</p>
	</div>
	<div>
		<label class="lbl" for="as-alg">Token signing</label>
		<select class="in" id="as-alg" bind:value={value.signing_alg}>
			<option value="RS256">RS256 (works with every app)</option>
			<option value="ES256">ES256 (smaller and faster)</option>
		</select>
		<p class="hint">Choose ES256 only if {appName} supports it. A change applies to the next sign-in or refresh.</p>
	</div>
	<div class="wide"><UriList id="as-logout" label="Sign-out redirect URIs" bind:uris={value.post_logout_redirect_uris} hint="Where {appName} may send people after signing out. Optional." /></div>
	<div class="wide"><label class="lbl" for="as-bc">Back-channel logout URI</label><input class="in" id="as-bc" type="url" bind:value={value.backchannel_logout_uri} placeholder="Not set" /><p class="hint">Lets Guardian sign users out of {appName} at once.</p></div>
</div>

<div class="switches">
	<label class="switch">
		<span><strong>Skip the consent screen</strong><span class="hint block">For apps you run yourself.</span></span>
		<input type="checkbox" bind:checked={value.is_first_party} />
	</label>
	<label class="switch">
		<span><strong>Require two-factor</strong><span class="hint block">Signing in to {appName} asks for a code, or sets two-factor up first.</span></span>
		<input type="checkbox" bind:checked={value.require_mfa} />
	</label>
</div>

<fieldset class="scopes">
	<legend class="lbl">Scopes {appName} may ask for</legend>
	{#each scopes as s (s.name)}
		<label class="scope">
			<input type="checkbox" checked={value.scopes.includes(s.name)} disabled={s.name === 'openid'} onchange={(e) => toggleScope(s.name, e.currentTarget.checked)} />
			<span><code>{s.name}</code><span class="hint block">{s.name === 'openid' ? 'Always on: needed to sign in.' : s.description}</span></span>
		</label>
	{/each}
</fieldset>

<style>
	.wide {
		grid-column: 1 / -1;
	}
	.switches {
		display: flex;
		flex-direction: column;
		gap: 14px;
		margin-top: 20px;
	}
	.switch {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 18px;
		cursor: pointer;
	}
	.switch strong {
		font-weight: 600;
	}
	.switch input {
		width: 20px;
		height: 20px;
		accent-color: var(--accent);
		flex: none;
	}
	.block {
		display: block;
		margin: 0;
	}
	.scopes {
		border: 0;
		padding: 0;
		margin: 20px 0 0;
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(230px, 1fr));
		gap: 10px 18px;
	}
	.scopes legend {
		margin-bottom: 8px;
	}
	.scope {
		display: flex;
		gap: 10px;
		align-items: flex-start;
		cursor: pointer;
	}
	.scope input {
		margin-top: 3px;
		accent-color: var(--accent);
	}
	code {
		font: 500 14px ui-monospace, Menlo, Consolas, monospace;
	}
</style>
