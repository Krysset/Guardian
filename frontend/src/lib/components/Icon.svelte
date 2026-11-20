<!-- The management UI's icons: 24px stroke icons from the design board, drawn in the current colour. -->
<script lang="ts" module>
	const paths = {
		profile: '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
		security: '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
		sessions: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
		apps: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
		groups: '<circle cx="9" cy="9" r="3.5"/><circle cx="17" cy="10" r="2.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M15 20a4.5 4.5 0 0 1 7 0"/>',
		data: '<path d="M12 3v12M7 10l5 5 5-5M4 21h16"/>',
		overview: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
		audit: '<path d="M8 4h12M8 12h12M8 20h12M3.5 4h.01M3.5 12h.01M3.5 20h.01"/>',
		deleted: '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
		warning: '<path d="M12 3l10 18H2zM12 10v5M12 18h.01"/>',
		eye: '<path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
		check: '<path d="M5 12l5 5 9-10"/>',
		shield: '<path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/>',
		plus: '<path d="M12 5v14M5 12h14"/>',
		list: '<path d="M8 4h12M8 12h12M8 20h12M3.5 4h.01M3.5 12h.01M3.5 20h.01"/>'
	} as const;
	export type IconName = keyof typeof paths;
</script>

<script lang="ts">
	let { name, size = 18 }: { name: IconName; size?: number } = $props();
</script>

<svg
	width={size}
	height={size}
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="2"
	stroke-linecap="round"
	stroke-linejoin="round"
	aria-hidden="true">{@html paths[name]}</svg
>
