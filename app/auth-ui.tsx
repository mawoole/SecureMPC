import Link from "next/link";
import type { ReactNode } from "react";

export function AuthLayout({
  children,
  eyebrow,
  title,
}: {
  children: ReactNode;
  eyebrow: string;
  title: string;
}) {
  return (
    <main className="auth-page">
      <section className="auth-brand-panel">
        <Link className="auth-brand" href="/">
          <span className="brand-mark" aria-hidden="true">
            T
          </span>
          <span>
            <strong>MCP TrustMap</strong>
            <small>Autonomous trust & security workspace</small>
          </span>
        </Link>
        <div className="auth-promise">
          <span className="section-kicker">SÉCURITÉ MCP MULTI-CLIENT</span>
          <h1>Une identité indépendante pour chaque organisation.</h1>
          <p>
            Comptes vérifiés, rôles cloisonnés, double approbation et MFA sans
            dépendance à un espace ChatGPT.
          </p>
          <ul>
            <li>Isolation stricte des données par organisation</li>
            <li>Rôles Admin, Auditor et Reader</li>
            <li>Invitations et récupération sécurisées par e-mail</li>
          </ul>
        </div>
      </section>
      <section className="auth-form-panel">
        <div className="auth-form-card">
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
          {children}
        </div>
      </section>
    </main>
  );
}

export function FormMessage({
  children,
  tone = "error",
}: {
  children: ReactNode;
  tone?: "error" | "success" | "info";
}) {
  return (
    <p className={`auth-message ${tone}`} role={tone === "error" ? "alert" : "status"}>
      {children}
    </p>
  );
}

export function authErrorMessage(error: unknown): string {
  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof error.message === "string"
  ) {
    return error.message;
  }
  return "L’opération n’a pas pu être terminée.";
}

export function safeReturnTo(value: string | null): string {
  if (!value || !value.startsWith("/") || value.startsWith("//")) return "/";
  try {
    const url = new URL(value, "https://mcp-trustmap.local");
    return url.origin === "https://mcp-trustmap.local"
      ? `${url.pathname}${url.search}${url.hash}`
      : "/";
  } catch {
    return "/";
  }
}
