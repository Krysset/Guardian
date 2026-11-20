import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// The management UI is a single-page app: adapter-static writes the script and style files under /_app and one
// fallback page that nginx serves for every path under /account and /admin. The sign-in pages, the API and
// /static/ (the font, the background and the logo) come from the backend on the same origin.
const backend = process.env.GUARDIAN_BACKEND ?? 'http://localhost:3001';

export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				runes: ({ filename }) => (filename.split(/[/\\]/).includes('node_modules') ? undefined : true)
			},
			adapter: adapter({ fallback: '200.html' }),
			// The fallback page starts the app with an inline script; its hash goes into a CSP <meta> tag, so the
			// page needs no 'unsafe-inline'. nginx sends the rest of the headers.
			csp: {
				mode: 'hash',
				directives: {
					'default-src': ['none'],
					'script-src': ['self'],
					'style-src': ['self'],
					'img-src': ['self', 'https:', 'data:'],
					'font-src': ['self'],
					'connect-src': ['self'],
					'base-uri': ['none'],
					'form-action': ['self']
				}
			}
		})
	],
	server: {
		// Development: open http://localhost:3000. Vite serves the management UI and forwards everything else
		// (sign-in pages, /api, /static, OIDC) to the backend, so both share one origin and the session cookie.
		proxy: {
			// Vite's own paths (/@vite, /@fs, /node_modules, /src, /.svelte-kit) stay with Vite.
			'^/(?!(@|(account|admin|_app|node_modules|src|\\.svelte-kit)(/|$))).*': { target: backend, xfwd: true }
		}
	}
});
