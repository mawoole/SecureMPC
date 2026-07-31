"use client";

import { FormEvent, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
} from "../auth-ui";

export default function SignupPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setMessage("");
    if (password !== confirmation) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }
    setPending(true);
    try {
      const result = await authClient.signUp.email({
        name,
        email,
        password,
        callbackURL: "/onboarding",
      });
      if (result.error) {
        setError(authErrorMessage(result.error));
        return;
      }
      setMessage(
        "Compte créé. Consultez votre messagerie pour confirmer votre adresse.",
      );
    } catch (caught) {
      setError(authErrorMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthLayout eyebrow="NOUVEL ESPACE" title="Créer votre compte">
      <form className="auth-form" onSubmit={submit}>
        <label>
          Nom complet
          <input
            autoComplete="name"
            maxLength={120}
            onChange={(event) => setName(event.target.value)}
            required
            value={name}
          />
        </label>
        <label>
          Adresse professionnelle
          <input
            autoComplete="email"
            onChange={(event) => setEmail(event.target.value)}
            required
            type="email"
            value={email}
          />
        </label>
        <label>
          Mot de passe
          <input
            autoComplete="new-password"
            minLength={12}
            onChange={(event) => setPassword(event.target.value)}
            required
            type="password"
            value={password}
          />
          <small>12 caractères minimum. Une phrase de passe est recommandée.</small>
        </label>
        <label>
          Confirmer le mot de passe
          <input
            autoComplete="new-password"
            minLength={12}
            onChange={(event) => setConfirmation(event.target.value)}
            required
            type="password"
            value={confirmation}
          />
        </label>
        {error ? <FormMessage>{error}</FormMessage> : null}
        {message ? <FormMessage tone="success">{message}</FormMessage> : null}
        <button className="button primary auth-submit" disabled={pending}>
          {pending ? "Création…" : "Créer le compte"}
        </button>
      </form>
      <div className="auth-links">
        <span>
          Vous avez déjà un compte ? <a href="/login">Se connecter</a>
        </span>
      </div>
    </AuthLayout>
  );
}
