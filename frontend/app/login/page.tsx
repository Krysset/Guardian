export default function LoginPage() {
	return (
		<body>
			<main className="container">
				<article>
					<header>Login to your account</header>
					<form>
						<fieldset role="group">
							<input type="username" placeholder="Username" required />
							<input type="password" placeholder="Password" required />
							<button type="submit">Login</button>
						</fieldset>
					</form>
				</article>
			</main>
		</body>
	);
}
