"use client";

import { FormEvent, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
} from "../auth-ui";

export default function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [error, setError] = useState("");
  const [sent, setSent] = useState(false);
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const result = await authClient.requestPasswordReset({
        email,
        redirectTo: `${window.location.origin}/reset-password`,
      });
      if (result.error) {
        setError(authErrorMessage(result.error));
        return;
      }
      setSent(true);
    } catch (caught) {
      setError(authErrorMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthLayout eyebrow="RÉCUPÉRATION" title="Réinitialiser le mot de passe">
      {sent ? (
        <>
          <FormMessage tone="success">
            Si cette adresse correspond à un compte, un lien valable une heure
            vient d’être envoyé.
          </FormMessage>
          <a className="button secondary auth-submit" href="/login">
            Revenir à la connexion
          </a>
        </>
      ) : (
        <form className="auth-form" onSubmit={submit}>
          <p className="auth-intro">
            Saisissez l’adresse utilisée lors de votre inscription.
          </p>
          <label>
            Adresse e-mail
            <input
              autoComplete="email"
              onChange={(event) => setEmail(event.target.value)}
              required
              type="email"
              value={email}
            />
          </label>
          {error ? <FormMessage>{error}</FormMessage> : null}
          <button className="button primary auth-submit" disabled={pending}>
            {pending ? "Envoi…" : "Envoyer le lien"}
          </button>
        </form>
      )}
    </AuthLayout>
  );
}
