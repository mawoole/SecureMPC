"use client";

import { FormEvent, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
  safeReturnTo,
} from "../auth-ui";

export default function LoginPage() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    const returnTo = safeReturnTo(
      new URLSearchParams(window.location.search).get("returnTo"),
    );
    try {
      const result = await authClient.signIn.email({
        email,
        password,
        rememberMe: true,
        callbackURL: returnTo,
      });
      if (result.error) {
        setError(
          result.error.status === 403
            ? "Confirmez d’abord votre adresse e-mail à l’aide du message reçu."
            : authErrorMessage(result.error),
        );
        return;
      }
      window.location.href = returnTo;
    } catch (caught) {
      setError(authErrorMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthLayout eyebrow="ACCÈS SÉCURISÉ" title="Se connecter">
      <form className="auth-form" onSubmit={submit}>
        <label>
          Adresse e-mail
          <input
            autoComplete="email"
            inputMode="email"
            onChange={(event) => setEmail(event.target.value)}
            required
            type="email"
            value={email}
          />
        </label>
        <label>
          Mot de passe
          <input
            autoComplete="current-password"
            minLength={12}
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
          />
        </label>
        {error ? <FormMessage>{error}</FormMessage> : null}
        <button className="button primary auth-submit" disabled={pending}>
          {pending ? "Connexion…" : "Se connecter"}
        </button>
      </form>
      <div className="auth-links">
        <a href="/forgot-password">Mot de passe oublié ?</a>
        <span>
          Nouveau sur MCP TrustMap ? <a href="/signup">Créer un compte</a>
        </span>
      </div>
    </AuthLayout>
  );
}
