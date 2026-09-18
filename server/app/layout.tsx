import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Synthaea - Control Plane",
  description: "EDR/XDR control plane for fleet management and detection",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
