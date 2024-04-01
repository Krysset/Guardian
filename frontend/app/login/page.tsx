export default function Login() {
	return (
		<body>
			<main className="container">
				<form>
					<input type="username" placeholder="Username" required />
					<input type="password" placeholder="Password" required />
					<button type="submit">Login</button>
				</form>
			</main>
		</body>
	);
}
