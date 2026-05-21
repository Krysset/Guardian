import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
	title: {
		default: "Guardian",
		template: "%s | Guardian"
	},
	description: "Account microservice, Guardian",
	generator: "Next.js",
	applicationName: "Guardian",
	referrer: "origin-when-cross-origin",
	keywords: ["Next.js", "React", "JavaScript"],
	authors: [{ name: "Max Hagman", url: "maxhagman.se" }],
	creator: "Max Hagman",
	formatDetection: {
		email: true,
		address: true,
		telephone: true
	},
	icons: {
		icon: [
			{
				media: "(prefers-color-scheme: light)",
				url: "/images/icon-dark-head.svg",
				href: "/images/icon-dark-head.svg"
			},
			{
				media: "(prefers-color-scheme: dark)",
				url: "/images/icon-light-head.svg",
				href: "/images/icon-light-head.svg"
			}
		]
	}
};

export default function RootLayout({
	children
}: Readonly<{
	children: React.ReactNode;
}>) {
	return (
		<html lang="en">
			<body className={inter.className}>{children}</body>
		</html>
	);
}
