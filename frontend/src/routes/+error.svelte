<!-- Errors while opening a page of the management UI: a page that does not exist, the admin area for someone
     who is not an administrator, or a session that must pass two-factor first. -->
<script lang="ts">
	import { page } from '$app/state';

	const mfa = $derived(page.error?.message === 'mfa_required');
	const title = $derived(
		mfa ? 'Sign in again with two-factor' : page.status === 404 ? 'Page not found' : page.status === 403 ? 'Not for this account' : 'Something went wrong'
	);
</script>

<svelte:head><title>{title} · Guardian</title></svelte:head>

<main class="error">
	<div class="card">
		<h1>{title}</h1>
		{#if mfa}
			<p>The admin area needs a session that passed two-factor. Sign out, then sign in again with your authenticator app.</p>
			<p><a class="btn" href="/logout" data-sveltekit-reload>Sign out</a></p>
		{:else}
			<p>{page.status === 404 ? 'There is no page at this address.' : page.error?.message}</p>
			<p><a class="btn" href="/account">Go to your account</a></p>
		{/if}
	</div>
</main>

<style>
	.error {
		min-height: 100vh;
		display: grid;
		place-items: center;
		padding: 16px;
		box-sizing: border-box;
	}
	.card {
		max-width: 480px;
	}
	h1 {
		font: 600 24px/1.25 Figtree, system-ui, sans-serif;
		margin: 0 0 8px;
	}
	p {
		margin: 0 0 16px;
		color: var(--mute);
	}
	p:last-child {
		margin: 0;
	}
</style>
