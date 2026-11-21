// The state behind the "Confirm it's you" dialog (AC8). A protected change answers 403 reauth_required; the API
// client then calls confirmIdentity, which opens the dialog and resolves once the user confirmed (true) or
// cancelled (false). The dialog itself is ReauthDialog.svelte, placed once in the root layout.

type Pending = { reason: string; done: (ok: boolean) => void };

export const reauth = $state<{ pending: Pending | null }>({ pending: null });

/** Opens the dialog for the given change ("change your email address"). */
export function confirmIdentity(reason: string): Promise<boolean> {
	// A second protected call while the dialog is open waits for the same answer.
	const open = reauth.pending;
	if (open) {
		return new Promise((resolve) => {
			const previous = open.done;
			open.done = (ok) => {
				previous(ok);
				resolve(ok);
			};
		});
	}
	return new Promise((resolve) => {
		reauth.pending = {
			reason,
			done: (ok) => {
				reauth.pending = null;
				resolve(ok);
			}
		};
	});
}
