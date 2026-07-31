"use client";

import { useMemo, useState } from "react";
import type { McpServer } from "../lib/audit-engine";
import type {
  EnterpriseCapabilities,
  EnterpriseRole,
  ExceptionDecision,
} from "../lib/enterprise-authorization";
import {
  riskExceptionStatus,
  type RiskException,
} from "../lib/finding-exceptions";
import {
  createEnterprisePolicyPack,
  createEnterpriseSummary,
} from "../lib/trustmap-modules";
import {
  createEncryptedRiskExceptionBundle,
  decryptRiskExceptionBundle,
  mergeRiskExceptions,
} from "../lib/trustmap-governance";

export type SharedExceptionSyncState = {
  phase: "connecting" | "syncing" | "synced" | "unavailable" | "error";
  message: string;
  identity?: string;
  workspaceRef?: string;
  kmsLabel?: string;
  kmsKeyId?: string;
  lastSyncedAt?: string | null;
  role?: EnterpriseRole;
  capabilities?: EnterpriseCapabilities;
  localPreview?: boolean;
};

const roleLabel: Record<EnterpriseRole, string> = {
  reader: "Lecteur",
  auditor: "Auditeur",
  admin: "Administrateur",
};

export function TrustMapEnterprise({
  servers,
  exceptions,
  onNotify,
  onExceptionsImported,
  sharedSync,
  onSyncNow,
  onExceptionDecision,
}: {
  servers: McpServer[];
  exceptions: RiskException[];
  onNotify: (message: string) => void;
  onExceptionsImported: (exceptions: RiskException[]) => void;
  sharedSync: SharedExceptionSyncState;
  onSyncNow: () => void;
  onExceptionDecision: (
    exceptionId: string,
    decision: ExceptionDecision,
  ) => Promise<void>;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [encryptedBundle, setEncryptedBundle] = useState("");
  const [encryptedFilename, setEncryptedFilename] = useState("");
  const [syncMessage, setSyncMessage] = useState("");
  const [syncError, setSyncError] = useState("");
  const [syncBusy, setSyncBusy] = useState(false);
  const [decisionBusy, setDecisionBusy] = useState("");
  const summary = useMemo(
    () => createEnterpriseSummary(servers, exceptions),
    [exceptions, servers],
  );
  const pendingExceptions = useMemo(
    () =>
      exceptions.filter(
        (exception) => riskExceptionStatus(exception) === "pending",
      ),
    [exceptions],
  );
  const canSync = sharedSync.capabilities?.canSync !== false;

  const decideException = async (
    exceptionId: string,
    decision: ExceptionDecision,
  ) => {
    setDecisionBusy(`${exceptionId}:${decision}`);
    try {
      await onExceptionDecision(exceptionId, decision);
    } finally {
      setDecisionBusy("");
    }
  };

  const downloadJson = (filename: string, value: unknown) => {
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(value, null, 2)], {
        type: "application/json;charset=utf-8",
      }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  const exportPolicyPack = () => {
    downloadJson(
      `mcp-trustmap-governance-${new Date().toISOString().slice(0, 10)}.json`,
      createEnterprisePolicyPack(servers, exceptions),
    );
    onNotify("Pack de gouvernance Enterprise exporté");
  };

  const exportEncryptedExceptions = async () => {
    setSyncBusy(true);
    setSyncError("");
    setSyncMessage("");
    try {
      const bundle = await createEncryptedRiskExceptionBundle(
        exceptions,
        passphrase,
      );
      downloadJson(
        `mcp-trustmap-exceptions-${new Date().toISOString().slice(0, 10)}.encrypted.json`,
        bundle,
      );
      setPassphrase("");
      setSyncMessage(
        `${exceptions.length} exception${exceptions.length > 1 ? "s" : ""} exportée${exceptions.length > 1 ? "s" : ""} dans un bundle chiffré.`,
      );
      onNotify("Registre d’exceptions chiffré et exporté");
    } catch (error) {
      setSyncError(
        error instanceof Error
          ? error.message
          : "Le registre n’a pas pu être chiffré.",
      );
    } finally {
      setSyncBusy(false);
    }
  };

  const importEncryptedExceptions = async () => {
    setSyncBusy(true);
    setSyncError("");
    setSyncMessage("");
    try {
      if (!encryptedBundle) {
        throw new Error("Chargez d’abord un bundle d’exceptions chiffré.");
      }
      const imported = await decryptRiskExceptionBundle(
        encryptedBundle,
        passphrase,
      );
      const merged = mergeRiskExceptions(exceptions, imported);
      onExceptionsImported(merged);
      setPassphrase("");
      setEncryptedBundle("");
      setEncryptedFilename("");
      setSyncMessage(
        `${imported.length} exception${imported.length > 1 ? "s" : ""} vérifiée${imported.length > 1 ? "s" : ""}, ${merged.length} décision${merged.length > 1 ? "s" : ""} dans le registre fusionné.`,
      );
      onNotify("Exceptions chiffrées vérifiées et fusionnées");
    } catch (error) {
      setSyncError(
        error instanceof Error
          ? error.message
          : "Le bundle d’exceptions n’a pas pu être importé.",
      );
    } finally {
      setSyncBusy(false);
    }
  };

  const readiness = [
    {
      label: "Inventaire",
      value: summary.servers ? "Opérationnel" : "À connecter",
      ready: summary.servers > 0,
      detail: `${summary.servers} serveur${summary.servers > 1 ? "s" : ""} sous gestion`,
    },
    {
      label: "Responsabilités",
      value: `${summary.ownershipCoverage}%`,
      ready: summary.ownershipCoverage === 100,
      detail: "Objectif : chaque serveur attribué",
    },
    {
      label: "Supply chain",
      value: `${summary.provenanceCoverage}%`,
      ready: summary.provenanceCoverage >= 80,
      detail: "Objectif : 80 % de preuves vérifiées",
    },
    {
      label: "Risques critiques",
      value: String(summary.openCritical),
      ready: summary.openCritical === 0,
      detail: "Objectif : aucun écart critique ouvert",
    },
  ];

  return (
    <section className="module-view enterprise-view">
      <div className="module-hero">
        <div>
          <span className="module-badge">TRUSTMAP ENTERPRISE</span>
          <h2>Pilotez la confiance MCP par équipe, preuve et exception.</h2>
          <p>
            Mesurez la préparation de votre organisation à partir de données
            réellement présentes dans cet espace de travail.
          </p>
        </div>
        <div className="readiness-score">
          <span>INDICE DE PRÉPARATION</span>
          <strong>{summary.readinessScore}</strong>
          <small>/ 100</small>
        </div>
      </div>

      <div className="readiness-grid">
        {readiness.map((item) => (
          <article key={item.label} className={item.ready ? "ready" : "attention"}>
            <span>{item.ready ? "✓" : "!"}</span>
            <div><small>{item.label}</small><strong>{item.value}</strong><p>{item.detail}</p></div>
          </article>
        ))}
      </div>

      <div className="enterprise-layout">
        <article className="module-card owners-card">
          <div className="module-card-head">
            <div><span className="section-kicker">RESPONSABILITÉ</span><h3>Posture par propriétaire</h3></div>
            <span className="count-badge">{summary.owners.length}</span>
          </div>
          <div className="owner-table">
            <div className="owner-row owner-head"><span>Équipe</span><span>Serveurs</span><span>Score</span><span>Critiques</span></div>
            {summary.owners.map((owner) => (
              <div className="owner-row" key={owner.owner}>
                <strong>{owner.owner}</strong>
                <span>{owner.servers}</span>
                <span>{owner.averageScore}/100</span>
                <span className={owner.openCritical ? "danger-text" : "success-text"}>{owner.openCritical}</span>
              </div>
            ))}
          </div>
        </article>

        <article className="module-card governance-card">
          <div className="module-card-head"><div><span className="section-kicker">GOUVERNANCE</span><h3>Registre des décisions</h3></div></div>
          <div className="governance-stat"><span>Exceptions actives</span><strong>{summary.activeExceptions}</strong></div>
          <div className="governance-stat"><span>Expirent sous 30 jours</span><strong>{summary.expiringExceptions}</strong></div>
          <p>
            Le pack exporté contient les objectifs de politique, la posture par
            responsable et les exceptions actives, sans configuration serveur.
          </p>
          <button className="button primary" onClick={exportPolicyPack}>
            Exporter le pack de gouvernance
          </button>
        </article>
      </div>
      <article className="module-card automatic-sync-card">
        <div className="module-card-head">
          <div>
            <span className="section-kicker">ESPACE PARTAGÉ · SSO</span>
            <h3>Synchronisation automatique des décisions</h3>
          </div>
          <span className={`sync-state ${sharedSync.phase}`}>
            <i aria-hidden="true" />
            {sharedSync.phase === "synced"
              ? "Synchronisé"
              : sharedSync.phase === "syncing"
                ? "Synchronisation"
                : sharedSync.phase === "connecting"
                  ? "Connexion"
                  : "Indisponible"}
          </span>
        </div>
        <p className="crypto-intro">
          L’identité transmise par la plateforme attribue chaque modification.
          Les exceptions sont chiffrées individuellement avant stockage avec
          une clé de données enveloppée.
        </p>
        <div className="sync-facts">
          <div>
            <span>Identité SSO</span>
            <strong>{sharedSync.identity || "Non authentifiée"}</strong>
          </div>
          <div>
            <span>Espace</span>
            <strong>
              {sharedSync.workspaceRef
                ? `…${sharedSync.workspaceRef}`
                : "En attente"}
            </strong>
          </div>
          <div>
            <span>Rôle effectif</span>
            <strong>
              {sharedSync.role
                ? roleLabel[sharedSync.role]
                : "En attente"}
            </strong>
            <small>Autorisation vérifiée côté serveur</small>
          </div>
          <div>
            <span>Gestion des clés</span>
            <strong>{sharedSync.kmsLabel || "Non configurée"}</strong>
            {sharedSync.kmsKeyId ? <small>{sharedSync.kmsKeyId}</small> : null}
          </div>
          <div>
            <span>Dernière synchronisation</span>
            <strong>
              {sharedSync.lastSyncedAt
                ? new Intl.DateTimeFormat("fr-FR", {
                    dateStyle: "short",
                    timeStyle: "short",
                  }).format(new Date(sharedSync.lastSyncedAt))
                : "Aucune"}
            </strong>
          </div>
        </div>
        <div className="automatic-sync-footer">
          <p role="status">{sharedSync.message}</p>
          <button
            className="button secondary"
            disabled={
              sharedSync.phase === "connecting" ||
              sharedSync.phase === "syncing" ||
              !canSync
            }
            onClick={onSyncNow}
          >
            Synchroniser maintenant
          </button>
        </div>
      </article>
      <article className="module-card approval-card">
        <div className="module-card-head">
          <div>
            <span className="section-kicker">SÉPARATION DES TÂCHES</span>
            <h3>Double approbation des exceptions critiques</h3>
          </div>
          <span className="count-badge">{pendingExceptions.length}</span>
        </div>
        <p className="crypto-intro">
          Une exception critique ne réduit jamais le risque avant deux
          validations provenant d’auditeurs distincts du demandeur. Le serveur
          vérifie l’identité, le rôle et l’unicité de chaque décision.
        </p>
        {pendingExceptions.length ? (
          <div className="approval-list">
            {pendingExceptions.map((exception) => (
              <div className="approval-row" key={exception.id}>
                <div>
                  <strong>
                    {exception.serverName} · {exception.findingTitle}
                  </strong>
                  <p>{exception.reason}</p>
                  <small>
                    {exception.approval?.approvals.length ?? 0}/
                    {exception.approval?.requiredApprovals ?? 2} approbations ·
                    expire le{" "}
                    {new Intl.DateTimeFormat("fr-FR", {
                      dateStyle: "short",
                    }).format(new Date(exception.expiresAt))}
                  </small>
                </div>
                <div className="approval-actions">
                  <button
                    className="button primary compact"
                    disabled={
                      !sharedSync.capabilities?.canApprove ||
                      Boolean(decisionBusy)
                    }
                    onClick={() =>
                      void decideException(exception.id, "approve")
                    }
                  >
                    {decisionBusy === `${exception.id}:approve`
                      ? "Validation…"
                      : "Approuver"}
                  </button>
                  {sharedSync.capabilities?.canReject ? (
                    <button
                      className="button secondary compact"
                      disabled={Boolean(decisionBusy)}
                      onClick={() =>
                        void decideException(exception.id, "reject")
                      }
                    >
                      {decisionBusy === `${exception.id}:reject`
                        ? "Rejet…"
                        : "Rejeter"}
                    </button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="approval-empty">
            <span aria-hidden="true">✓</span>
            <div>
              <strong>Aucune approbation critique en attente</strong>
              <p>
                Les exceptions non critiques restent gérées par les rôles
                auditeur et administrateur.
              </p>
            </div>
          </div>
        )}
        {!sharedSync.capabilities?.canApprove ? (
          <p className="role-hint">
            Votre rôle est en lecture seule pour les décisions d’approbation.
          </p>
        ) : null}
      </article>
      <article className="module-card exception-sync-card">
        <div className="module-card-head">
          <div>
            <span className="section-kicker">ÉCHANGE CONFIDENTIEL</span>
            <h3>Synchroniser le registre par bundle chiffré</h3>
          </div>
          <span className="crypto-badge">AES-256-GCM</span>
        </div>
        <p className="crypto-intro">
          Exportez le registre, transmettez le fichier par votre canal habituel
          et communiquez la phrase secrète séparément. L’import fusionne les
          décisions par identifiant et propage toujours une révocation.
        </p>
        <div className="exception-sync-grid">
          <label>
            Phrase secrète partagée
            <input
              type="password"
              value={passphrase}
              minLength={12}
              maxLength={256}
              autoComplete="new-password"
              onChange={(event) => setPassphrase(event.target.value)}
              placeholder="12 caractères minimum"
            />
          </label>
          <label className="file-field">
            Bundle reçu
            <input
              type="file"
              accept=".json,application/json"
              onChange={async (event) => {
                const file = event.target.files?.[0];
                if (!file) return;
                try {
                  if (file.size > 2 * 1_024 * 1_024) {
                    throw new Error("Le bundle dépasse la limite de 2 Mo.");
                  }
                  setEncryptedBundle(await file.text());
                  setEncryptedFilename(file.name);
                  setSyncError("");
                  setSyncMessage("Bundle chiffré chargé localement.");
                } catch (error) {
                  setSyncError(
                    error instanceof Error
                      ? error.message
                      : "Le bundle n’a pas pu être lu.",
                  );
                } finally {
                  event.target.value = "";
                }
              }}
            />
            <span>{encryptedFilename || "Aucun bundle chargé"}</span>
          </label>
          <div className="crypto-actions">
            <button
              className="button secondary"
              disabled={syncBusy || exceptions.length === 0}
              onClick={exportEncryptedExceptions}
            >
              Exporter chiffré
            </button>
            <button
              className="button primary"
              disabled={syncBusy || !encryptedBundle || !canSync}
              onClick={importEncryptedExceptions}
            >
              Déchiffrer et fusionner
            </button>
          </div>
        </div>
        {syncError ? (
          <p className="form-error" role="alert">
            {syncError}
          </p>
        ) : null}
        {syncMessage ? (
          <p className="crypto-message" role="status">
            {syncMessage}
          </p>
        ) : null}
      </article>
      <p className="enterprise-note">
        Le bundle reste disponible comme solution hors ligne. L’espace partagé
        conserve uniquement des enveloppes chiffrées, des versions et un
        journal pseudonymisé des écritures.
      </p>
    </section>
  );
}
