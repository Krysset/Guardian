import styles from "./page.module.css";

export default function Home() {
	return (
		<body>
			<main className={styles.main}>
				<div className={styles.description}>Welcome home!</div>
			</main>
		</body>
	);
}
