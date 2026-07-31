"use client";

import { FormEvent, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
} from "../auth-ui";

export default function ResetPasswordPage() {
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  const [complete, setComplete] = useState(false);
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    if (password !== confirmation) {
      setError("Les deux mots de passe ne correspondent pas.");
      return;
    }
    const token = new URLSearchParams(window.location.search).get("token");
    if (!token) {
      setError("Ce lien de récupération est absent, expiré ou invalide.");
      return;
    }
    setPending(true);
    try {
      const result = await authClient.resetPassword({
        newPassword: password,
        token,
      });
      if (result.error) {
        setError(authErrorMessage(result.error));
        return;
      }
      setComplete(true);
    } catch (caught) {
      setError(authErrorMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthLayout eyebrow="NOUVEAU SECRET" title="Choisir un mot de passe">
      {complete ? (
        <>
          <FormMessage tone="success">
            Le mot de passe a été modifié et les anciennes sessions ont été
            révoquées.
          </FormMessage>
          <a className="button primary auth-submit" href="/login">
            Se connecter
          </a>
        </>
      ) : (
        <form className="auth-form" onSubmit={submit}>
          <label>
            Nouveau mot de passe
            <input
              autoComplete="new-password"
              minLength={12}
              onChange={(event) => setPassword(event.target.value)}
              required
              type="password"
              value={password}
            />
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
          <button className="button primary auth-submit" disabled={pending}>
            {pending ? "Mise à jour…" : "Enregistrer"}
          </button>
        </form>
      )}
    </AuthLayout>
  );
}
