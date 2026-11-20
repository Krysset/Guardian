<script lang="ts">
	import '#lib/styles/app.css';
	import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
	import ReauthDialog from '#lib/components/ReauthDialog.svelte';
	import type { LayoutProps } from './$types';

	let { data, children }: LayoutProps = $props();
</script>

{@render children()}
<ReauthDialog hasTotp={data.me.mfa.totp ?? false} />
<ConfirmDialog />
