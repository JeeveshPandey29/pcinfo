import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Safex",
  description: "Safex reads local Windows security signals from this PC and explains them clearly.",
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
