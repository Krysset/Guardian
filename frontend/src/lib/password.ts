// Temporary passwords an administrator hands to a person (AD2, AD3): 16 characters from an alphabet without
// look-alikes (0 O 1 l I), in groups of four so they can be read out. About 91 bits.
const alphabet = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789';

export function generatePassword(): string {
	const out: string[] = [];
	const bytes = new Uint8Array(1);
	while (out.length < 16) {
		crypto.getRandomValues(bytes);
		// Only bytes below a multiple of the alphabet's length, so every character is equally likely.
		if (bytes[0] < 256 - (256 % alphabet.length)) out.push(alphabet[bytes[0] % alphabet.length]);
	}
	return out.join('').replace(/(.{4})(?!$)/g, '$1-');
}

/** Copies text to the clipboard; false where the browser does not allow it. */
export async function copyText(text: string): Promise<boolean> {
	try {
		await navigator.clipboard.writeText(text);
		return true;
	} catch {
		return false;
	}
}
