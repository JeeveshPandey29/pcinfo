import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SafePulse | Personal SOC",
  description: "An AI-powered personal SOC dashboard for everyday laptop users.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
