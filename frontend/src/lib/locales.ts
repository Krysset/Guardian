// The choices for a profile's language and time zone (AC1 and AD2), named in the browser's language.

const common = ['en-GB', 'en-US', 'sv-SE', 'nb-NO', 'da-DK', 'fi-FI', 'de-DE', 'fr-FR', 'es-ES', 'it-IT', 'nl-NL', 'pl-PL', 'pt-BR', 'pt-PT', 'ja-JP', 'ko-KR', 'zh-CN'];

/** Common languages, the browser's, and the current value, sorted by name. */
export function localeOptions(current: string): { tag: string; name: string }[] {
	const names = new Intl.DisplayNames(undefined, { type: 'language' });
	const tags = new Set(common);
	for (const l of navigator.languages) if (l.includes('-')) tags.add(l);
	if (current) tags.add(current);
	return [...tags]
		.map((tag) => {
			let name = tag;
			try {
				name = names.of(tag) ?? tag;
			} catch {
				// not a valid tag: show it as it is
			}
			return { tag, name };
		})
		.sort((a, b) => a.name.localeCompare(b.name));
}

/** Every IANA time zone the browser knows, and the current value if it is not one of them. */
export function zoneOptions(current: string): string[] {
	const all = Intl.supportedValuesOf('timeZone');
	return current && !all.includes(current) ? [current, ...all] : all;
}

/** The browser's own time zone. */
export const browserZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
