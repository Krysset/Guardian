<!-- AC9 Notifications: where Guardian's emails go and when the daily summary comes (at the top, so it is
     not buried under the panels, and always there so choosing Daily summary does not move the page), the security emails that always come, and how each
     other kind comes: right away, in the daily summary, or not at all. A panel shows only when the account
     can receive its kinds (group owners; Guardian administrators). Changes save at once, and say so where
     they were made: the chosen button flashes with "Saved" beside it, or "Saved" beside the hour; a failure
     shows under that row. -->
<script lang="ts">
	import { untrack } from 'svelte';
	import { fade } from 'svelte/transition';
	import Icon from '#lib/components/Icon.svelte';
	import { api, type Schema } from '#lib/api/client.ts';
	import { messageOf } from '#lib/format.ts';
	import type { PageProps } from './$types';

	type Delivery = Schema<'Delivery'>;

	let { data }: PageProps = $props();
	let view = $state(untrack(() => data.notifications));
	// Where the last change was made ("hour" or a kind), and how it went.
	let savedAt = $state('');
	let failedAt = $state('');
	let error = $state('');
	let timer: ReturnType<typeof setTimeout> | undefined;

	const panels = [
		{ key: 'owner', title: 'Groups you own' },
		{ key: 'admin', title: 'Guardian admin' }
	] as const;
	const choices: [Delivery, string][] = [
		['now', 'Right away'],
		['daily', 'Daily summary'],
		['off', 'Off']
	];
	const security = [
		'Your password was changed',
		'Two-factor was added or removed',
		'An administrator reset your two-factor',
		'Your email address is being changed',
		'Links to reset your password or confirm an address'
	];
	const hours = Array.from({ length: 24 }, (_, h) => h);
	const anyDaily = $derived(view.settings.some((s) => s.delivery === 'daily'));
	const zone = $derived(data.me.zoneinfo || 'UTC');

	async function save(at: string, body: { settings?: Record<string, Delivery>; summary_hour?: number }) {
		clearTimeout(timer);
		savedAt = failedAt = error = '';
		try {
			view = await api.put('/me/notifications', { body });
			savedAt = at;
			timer = setTimeout(() => (savedAt = ''), 2500);
		} catch (e) {
			failedAt = at;
			error = messageOf(e);
			view = await api.get('/me/notifications').catch(() => view);
		}
	}
</script>

<svelte:head><title>Notifications · Guardian</title></svelte:head>

<div class="ph"><h1>Notifications</h1><p>Choose which emails Guardian sends you, and when.</p></div>

<section class="card">
	<h2 class="sec-h">How emails reach you</h2>
	{#if view.email}
		<p class="text">To <strong>{view.email}</strong>. Change it under <a href="/account">Profile</a>.</p>
	{:else}
		<p class="note warn">You have no confirmed email address, so Guardian can't email you. Add one under <a href="/account">Profile</a>.</p>
	{/if}
	{#if view.settings.length}
		<div class="summary">
			<label class="lbl" for="hour">Daily summary at</label>
			<select class="in hour" id="hour" value={view.summary_hour} onchange={(e) => save('hour', { summary_hour: Number(e.currentTarget.value) })}>
				{#each hours as h (h)}<option value={h}>{String(h).padStart(2, '0')}:00</option>{/each}
			</select>
			{@render feedback('hour')}
			<p class="hint">
				{anyDaily ? 'One email with everything set to Daily summary, only when something happened.' : 'Used by notifications set to Daily summary. None are yet.'}
				Your time zone: {zone}, set under <a href="/account">Profile</a>.
			</p>
		</div>
	{/if}
</section>

{#snippet feedback(at: string)}
	<span class="saved" role="status">{#if savedAt === at}<span transition:fade={{ duration: 200 }}><Icon name="check" size={15} />Saved</span>{/if}</span>
	{#if failedAt === at}<p class="err-msg msg" role="alert">{error}</p>{/if}
{/snippet}

<section class="card">
	<h2 class="sec-h">Your account</h2>
	<p class="hint intro">These are about your account's security, so they always come right away.</p>
	<ul class="rows">
		{#each security as s (s)}<li class="row keep"><span>{s}</span><span class="badge always">Always sent</span></li>{/each}
	</ul>
</section>

{#each panels as p (p.key)}
	{@const rows = view.settings.filter((s) => s.panel === p.key)}
	{#if rows.length}
		<section class="card">
			<h2 class="sec-h">{p.title}</h2>
			<ul class="rows">
				{#each rows as s (s.kind)}
					<li class="row">
						<span><strong>{s.label}</strong><span class="hint block">{s.hint}</span></span>
						<div class="ctl">
							<div class="seg" role="radiogroup" aria-label={s.label}>
								{#each choices as [value, label] (value)}
									<label class:on={s.delivery === value} class:flash={savedAt === s.kind && s.delivery === value}>
										<input type="radio" name={s.kind} {value} checked={s.delivery === value} onchange={() => save(s.kind, { settings: { [s.kind]: value } })} />
										{label}
									</label>
								{/each}
							</div>
							{@render feedback(s.kind)}
						</div>
					</li>
				{/each}
			</ul>
		</section>
	{/if}
{/each}

<style>
	.text {
		margin: 14px 0 0;
	}
	.intro {
		margin: 6px 0 10px;
	}
	.note.warn {
		margin: 14px 0 0;
		color: var(--warn);
		background: var(--warnbg);
	}
	.msg {
		margin-top: 14px;
	}
	.always {
		color: var(--mute);
		flex: none;
	}
	.rows {
		list-style: none;
		margin: 0;
		padding: 0;
	}
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 18px;
		padding: 12px 0;
		border-top: 1px solid var(--line);
	}
	.row.keep {
		flex-wrap: nowrap;
	}
	.row:first-child {
		border-top: 0;
	}
	.row strong {
		font-weight: 600;
	}
	.block {
		display: block;
		margin: 0;
	}
	.seg {
		display: inline-flex;
		flex: none;
		border: 1px solid var(--line);
		border-radius: 8px;
		overflow: hidden;
		background: var(--field);
	}
	.seg label {
		position: relative;
		padding: 7px 14px;
		font-size: 14px;
		cursor: pointer;
		color: var(--mute);
		border-left: 1px solid var(--line);
		white-space: nowrap;
	}
	.seg label:first-child {
		border-left: 0;
	}
	.seg label.on {
		background: var(--sel);
		color: var(--ink);
		font-weight: 600;
	}
	.seg label:has(input:focus-visible) {
		outline: 2px solid var(--accent);
		outline-offset: -2px;
	}
	.seg input {
		position: absolute;
		opacity: 0;
		pointer-events: none;
	}
	.summary {
		margin-top: 18px;
		padding-top: 16px;
		border-top: 1px solid var(--line);
	}
	.hour {
		max-width: 160px;
		vertical-align: middle;
	}
	.summary .saved {
		margin-left: 12px;
		vertical-align: middle;
	}
	/* "Saved" sits beside what changed: left of the buttons, so nothing moves when it shows. */
	.ctl {
		position: relative;
		flex: none;
	}
	.ctl .saved {
		position: absolute;
		right: calc(100% + 12px);
		top: 50%;
		transform: translateY(-50%);
	}
	.ctl .err-msg {
		margin-top: 8px;
	}
	.saved span {
		display: inline-flex;
		align-items: center;
		gap: 5px;
		color: var(--ok);
		font-size: 14px;
		font-weight: 600;
		white-space: nowrap;
	}
	.seg label.flash {
		animation: flash 1.6s ease-out;
	}
	@keyframes flash {
		0%,
		30% {
			background: color-mix(in srgb, var(--ok) 28%, transparent);
			color: var(--ok);
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.seg label.flash {
			animation: none;
		}
	}
	@media (max-width: 640px) {
		.row:not(.keep) {
			flex-direction: column;
			align-items: stretch;
		}
		.seg {
			display: flex;
		}
		.seg label {
			flex: 1;
			text-align: center;
		}
		/* No room beside the buttons on a phone: "Saved" goes on the row's title line, at its end. */
		.ctl {
			position: static;
		}
		.row:not(.keep) {
			position: relative;
		}
		.row:not(.keep) > span:first-child {
			padding-right: 76px;
		}
		.ctl .saved {
			right: 0;
			top: 12px;
			transform: none;
		}
	}
</style>
