// A confirmation before something that cannot be undone ("Remove Zelda from Champions?"). The dialog is
// ConfirmDialog.svelte, placed once in the root layout; askConfirm resolves true when confirmed.

export type ConfirmRequest = {
	title: string;
	message?: string;
	confirm: string;
	danger?: boolean;
	/** The confirm button stays off until this is typed exactly (a username before erasing an account). */
	typeToConfirm?: string;
};

type Pending = ConfirmRequest & { done: (ok: boolean) => void };

export const confirmation = $state<{ pending: Pending | null }>({ pending: null });

export function askConfirm(request: ConfirmRequest): Promise<boolean> {
	confirmation.pending?.done(false);
	return new Promise((resolve) => {
		confirmation.pending = {
			...request,
			done: (ok) => {
				confirmation.pending = null;
				resolve(ok);
			}
		};
	});
}
