// How the management UI writes dates, times and partly hidden personal data. Dates use the browser's
// language and time zone; the account's own locale and time zone are for apps.

const day = 24 * 60 * 60 * 1000;

function startOfDay(d: Date): number {
	return new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
}

/** "12 Nov 2026". */
export function formatDate(iso: string | undefined | null): string {
	if (!iso) return '';
	return new Date(iso).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
}

/** "Today 08:12", "Yesterday 21:40", or "12 Nov 2026" further back. */
export function formatWhen(iso: string | undefined | null, now = new Date()): string {
	if (!iso) return '';
	const d = new Date(iso);
	const days = Math.round((startOfDay(now) - startOfDay(d)) / day);
	const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
	if (days === 0) return `Today ${time}`;
	if (days === 1) return `Yesterday ${time}`;
	return formatDate(iso);
}

/** "Now" within two minutes, otherwise as formatWhen. */
export function formatLastActive(iso: string, now = new Date()): string {
	return now.getTime() - new Date(iso).getTime() < 2 * 60 * 1000 ? 'Now' : formatWhen(iso, now);
}

/** "203.0.113.•••" or "2001:db8:85a3:8d3:•••": enough to recognise a network, not a person. */
export function maskIP(ip: string): string {
	if (!ip) return 'Unknown';
	if (ip.includes(':')) return ip.split(':').slice(0, 4).join(':') + ':•••';
	const parts = ip.split('.');
	return parts.length === 4 ? `${parts.slice(0, 3).join('.')}.•••` : ip;
}

/** "l•••@hyrule.example". */
export function maskEmail(address: string): string {
	const at = address.lastIndexOf('@');
	if (at < 1) return '•••';
	return address[0] + '•••' + address.slice(at);
}

/** A yyyy-mm-dd date from a date input, as the end of that day in the browser's time zone. */
export function endOfDay(date: string): string {
	return new Date(`${date}T23:59:59`).toISOString();
}

/** The yyyy-mm-dd of a moment in the browser's time zone, for a date input. */
export function dateInput(iso: string | undefined | null): string {
	if (!iso) return '';
	const d = new Date(iso);
	const pad = (n: number) => String(n).padStart(2, '0');
	return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/** The first letter of a name, for a tile without a picture. */
export function initial(name: string | undefined | null): string {
	return (name ?? '').trim().charAt(0).toUpperCase() || '?';
}

/** The error message to show for a failed call. */
export function messageOf(e: unknown): string {
	if (e && typeof e === 'object' && 'message' in e && typeof e.message === 'string' && e.message) {
		return e.message.endsWith('.') ? e.message : e.message + '.';
	}
	return 'Something went wrong. Try again.';
}

// formatDays says a number of days the way people say it: whole or half years ("half a year", "1 year",
// "1 and a half years"), else whole weeks ("1 week", "26 weeks"), else days. Months are never used: they
// differ in length. A half year is 182 or 183 days.
export function formatDays(days: number): string {
	const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
	if (days >= 182) {
		if (days % 365 === 0) return plural(days / 365, 'year');
		const halves = Math.round(days / 182.5);
		if (halves % 2 === 1 && Math.abs(days - halves * 182.5) <= 0.5) {
			const whole = (halves - 1) / 2;
			return whole === 0 ? 'half a year' : `${whole} and a half years`;
		}
	}
	if (days > 0 && days % 7 === 0) return plural(days / 7, 'week');
	return plural(days, 'day');
}
