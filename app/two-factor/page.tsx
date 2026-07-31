"use client";

import { FormEvent, useState } from "react";
import { authClient } from "../../lib/auth/client";
import {
  AuthLayout,
  authErrorMessage,
  FormMessage,
} from "../auth-ui";

export default function TwoFactorPage() {
  const [code, setCode] = useState("");
  const [backupMode, setBackupMode] = useState(false);
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setPending(true);
    setError("");
    try {
      const result = backupMode
        ? await authClient.twoFactor.verifyBackupCode({
            code: code.trim(),
            disableSession: false,
            trustDevice: true,
          })
        : await authClient.twoFactor.verifyTotp({
            code: code.replace(/\s/g, ""),
            trustDevice: true,
          });
      if (result.error) {
        setError(authErrorMessage(result.error));
        return;
      }
      window.location.href = "/";
    } catch (caught) {
      setError(authErrorMessage(caught));
    } finally {
      setPending(false);
    }
  }

  return (
    <AuthLayout eyebrow="SECOND FACTEUR" title="Confirmer votre identité">
      <form className="auth-form" onSubmit={submit}>
        <p className="auth-intro">
          {backupMode
            ? "Utilisez l’un des codes de secours enregistrés lors de l’activation."
            : "Saisissez le code à six chiffres généré par votre application d’authentification."}
        </p>
        <label>
          {backupMode ? "Code de secours" : "Code d’authentification"}
          <input
            autoComplete="one-time-code"
            inputMode={backupMode ? "text" : "numeric"}
            maxLength={backupMode ? 32 : 6}
            onChange={(event) => setCode(event.target.value)}
            required
            value={code}
          />
        </label>
        {error ? <FormMessage>{error}</FormMessage> : null}
        <button className="button primary auth-submit" disabled={pending}>
          {pending ? "Vérification…" : "Vérifier"}
        </button>
        <button
          className="auth-text-button"
          onClick={() => {
            setBackupMode((current) => !current);
            setCode("");
            setError("");
          }}
          type="button"
        >
          {backupMode
            ? "Utiliser l’application d’authentification"
            : "Utiliser un code de secours"}
        </button>
      </form>
    </AuthLayout>
  );
}
