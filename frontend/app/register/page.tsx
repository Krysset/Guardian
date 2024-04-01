export default function RegisterPage() {
	return (
		<body>
			<main className="container">
				<article>
					<header>Register for an account</header>
					<form>
						<input type="email" placeholder="Email" required />
						<fieldset role="group" id="pw">
							<input type="password" placeholder="A unique Password" required />
							<input type="password" placeholder="Repeat password" required />{" "}
						</fieldset>
						<small>
							<b>Do not use sensitive data!</b> I'm still learning how to secure your data!
						</small>
						<button type="submit">Register</button>
					</form>
				</article>
			</main>
		</body>
	);
}
