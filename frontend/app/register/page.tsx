"use client";
import { useFormState } from "react-dom";
import axios from "axios";

export default function RegisterPage() {
	async function processForm(prevState: any, formData: FormData) {
		const formJson = Object.fromEntries(formData.entries());
		const username = formJson.username.toString();
		const password = formJson.password.toString();
		const password2 = formJson.password2.toString();

		try {
			validateUsername(username);
		} catch (error: any) {
			alert(error.message);
			return;
		}
		try {
			validatePassword(password, password2);
		} catch (error: any) {
			alert(error.message);
			return;
		}

		await register(username, password);
	}

	const minUsernameLength = 3;
	const maxUsernameLength = 20;
	const minPasswordLength = 8;
	const maxPasswordLength = 100;

	const [message, formAction] = useFormState(processForm, null);

	return (
		<body>
			<main className="container">
				<article>
					<header>Register for an account</header>
					<form action={formAction}>
						<input
							type="username"
							name="username"
							placeholder="Username"
							required
							autoFocus
							minLength={minUsernameLength}
							maxLength={maxUsernameLength}
						/>
						<fieldset role="group">
							<input
								type="password"
								name="password"
								placeholder="A unique Password"
								required
								minLength={minPasswordLength}
								maxLength={maxPasswordLength}
							/>
							<input type="password" name="password2" placeholder="Repeat password" required />{" "}
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

function validateUsername(username: string) {
	// Minimum three characters, maximum twenty characters (alphanumeric)
	if (!/^[a-zA-Z0-9]{3,20}$/.test(username)) throw new Error("Username must be alphanumeric");
	return true;
}

function validatePassword(password: string, password2: string) {
	// throw errors instead of alerting
	if (password !== password2) throw new Error("Passwords do not match");
	// Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character
	if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,100}$/.test(password))
		throw new Error(
			"Password must contain at least one uppercase letter, one lowercase letter, one number and one special character"
		);
	return true;
}

function register(username: string, password: string) {
	return axios.post("/api/register", { username, password });
}
