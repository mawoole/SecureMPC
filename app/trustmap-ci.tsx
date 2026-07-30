"use client";

import { useMemo, useState } from "react";
import type { McpServer, Severity } from "../lib/audit-engine";
import type { RiskException } from "../lib/finding-exceptions";
import {
  createMultiEnvironmentWorkflow,
  createCiCommand,
  DEFAULT_TRUSTMAP_CI_PROFILES,
  evaluateCiGate,
  type TrustMapCiPolicyProfile,
} from "../lib/trustmap-modules";
import {
  createPolicySigningIdentity,
  signCiPolicyProfiles,
  verifySignedCiPolicy,
} from "../lib/trustmap-governance";

function downloadJson(filename: string, value: unknown) {
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
}

async function readBoundedFile(file: File, maximumBytes = 256 * 1_024) {
  if (file.size > maximumBytes) {
    throw new Error("Le fichier dépasse la limite de 256 Ko.");
  }
  return file.text();
}

export function TrustMapCi({
  servers,
  exceptions,
  onNotify,
}: {
  servers: McpServer[];
  exceptions: RiskException[];
  onNotify: (message: string) => void;
}) {
  const [profiles, setProfiles] = useState<TrustMapCiPolicyProfile[]>(() =>
    DEFAULT_TRUSTMAP_CI_PROFILES.map((profile) => ({ ...profile })),
  );
  const [activeProfileId, setActiveProfileId] = useState("production");
  const [signerLabel, setSignerLabel] = useState("Équipe sécurité");
  const [signingPassphrase, setSigningPassphrase] = useState("");
  const [identityDocument, setIdentityDocument] = useState("");
  const [identityFilename, setIdentityFilename] = useState("");
  const [policyDocument, setPolicyDocument] = useState("");
  const [policyFilename, setPolicyFilename] = useState("");
  const [expectedKeyId, setExpectedKeyId] = useState("");
  const [observedKeyId, setObservedKeyId] = useState("");
  const [signatureMessage, setSignatureMessage] = useState("");
  const [signatureError, setSignatureError] = useState("");
  const [cryptoBusy, setCryptoBusy] = useState(false);
  const activeProfile =
    profiles.find((profile) => profile.id === activeProfileId) ?? profiles[0];
  const enabledProfiles = useMemo(
    () => profiles.filter((profile) => profile.enabled),
    [profiles],
  );
  const generated = useMemo(() => {
    try {
      return {
        command: createCiCommand(activeProfile),
        workflow: createMultiEnvironmentWorkflow(enabledProfiles),
        error: "",
      };
    } catch (error) {
      return {
        command: "",
        workflow: "",
        error:
          error instanceof Error
            ? error.message
            : "La politique CI n’est pas valide.",
      };
    }
  }, [activeProfile, enabledProfiles]);
  const { command, workflow, error: generationError } = generated;
  const gate = useMemo(
    () => evaluateCiGate(servers, exceptions, activeProfile.failOn),
    [activeProfile.failOn, exceptions, servers],
  );

  const updateActiveProfile = (
    update: Partial<TrustMapCiPolicyProfile>,
  ) => {
    setProfiles((current) =>
      current.map((profile) =>
        profile.id === activeProfile.id
          ? { ...profile, ...update }
          : profile,
      ),
    );
  };

  const toggleProfile = (id: string, enabled: boolean) => {
    if (!enabled && enabledProfiles.length === 1) {
      onNotify("Au moins une politique CI doit rester active");
      return;
    }
    setProfiles((current) =>
      current.map((profile) =>
        profile.id === id ? { ...profile, enabled } : profile,
      ),
    );
  };

  const copy = async (value: string, label: string) => {
    await navigator.clipboard.writeText(value);
    onNotify(`${label} copié dans le presse-papiers`);
  };

  const createIdentity = async () => {
    setCryptoBusy(true);
    setSignatureError("");
    setSignatureMessage("");
    try {
      const identity = await createPolicySigningIdentity(
        signerLabel,
        signingPassphrase,
      );
      const serialized = JSON.stringify(identity, null, 2);
      setIdentityDocument(serialized);
      setIdentityFilename("Identité créée dans cette session");
      setExpectedKeyId(identity.keyId);
      setObservedKeyId(identity.keyId);
      downloadJson(
        `mcp-trustmap-signing-identity-${new Date().toISOString().slice(0, 10)}.json`,
        identity,
      );
      setSignatureMessage(
        "Identité créée et téléchargée. Conservez ce fichier chiffré dans un coffre.",
      );
      onNotify("Identité de signature chiffrée créée");
    } catch (error) {
      setSignatureError(
        error instanceof Error
          ? error.message
          : "L’identité n’a pas pu être créée.",
      );
    } finally {
      setCryptoBusy(false);
    }
  };

  const signPolicy = async () => {
    setCryptoBusy(true);
    setSignatureError("");
    setSignatureMessage("");
    try {
      if (!identityDocument) {
        throw new Error("Créez ou chargez d’abord une identité de signature.");
      }
      const policy = await signCiPolicyProfiles(
        profiles,
        identityDocument,
        signingPassphrase,
      );
      downloadJson(
        `mcp-trustmap-ci-policy-${new Date().toISOString().slice(0, 10)}.signed.json`,
        policy,
      );
      setObservedKeyId(policy.signer.keyId);
      setSignatureMessage(
        `Politique signée par ${policy.signer.label} et téléchargée.`,
      );
      setSigningPassphrase("");
      onNotify("Politique CI signée et exportée");
    } catch (error) {
      setSignatureError(
        error instanceof Error
          ? error.message
          : "La politique n’a pas pu être signée.",
      );
    } finally {
      setCryptoBusy(false);
    }
  };

  const verifyPolicy = async () => {
    setCryptoBusy(true);
    setSignatureError("");
    setSignatureMessage("");
    try {
      if (!policyDocument) {
        throw new Error("Chargez d’abord un fichier de politique signée.");
      }
      const result = await verifySignedCiPolicy(
        policyDocument,
        expectedKeyId,
      );
      setObservedKeyId(result.keyId);
      if (!result.trusted) {
        setSignatureMessage(
          "Signature valide, mais identité non approuvée. Comparez puis saisissez l’empreinte attendue avant de charger les profils.",
        );
        return;
      }
      setProfiles(result.profiles.map((profile) => ({ ...profile })));
      setActiveProfileId(
        result.profiles.find((profile) => profile.enabled)?.id ??
          result.profiles[0].id,
      );
      setSignatureMessage(
        `Signature et empreinte validées pour ${result.signerLabel}. Les profils ont été chargés.`,
      );
      onNotify("Politique signée vérifiée et chargée");
    } catch (error) {
      setSignatureError(
        error instanceof Error
          ? error.message
          : "La politique signée n’a pas pu être vérifiée.",
      );
    } finally {
      setCryptoBusy(false);
    }
  };

  return (
    <section className="module-view ci-view">
      <div className="module-hero">
        <div>
          <span className="module-badge">TRUSTMAP CI</span>
          <h2>Transformez vos règles MCP en garde-fou de livraison.</h2>
          <p>
            Appliquez des exigences distinctes au développement, à la
            préproduction et à la production, puis publiez les écarts dans
            Code Scanning.
          </p>
        </div>
        <div className={`gate-preview ${gate.passed ? "passed" : "blocked"}`}>
          <span>{gate.passed ? "✓" : "!"}</span>
          <div>
            <small>SIMULATION · {activeProfile.name.toUpperCase()}</small>
            <strong>
              {gate.passed ? "Livraison autorisée" : "Livraison bloquée"}
            </strong>
            <p>{gate.label}</p>
          </div>
        </div>
      </div>

      <div className="policy-profile-grid" aria-label="Profils de politique CI">
        {profiles.map((profile) => (
          <article
            key={profile.id}
            className={`${profile.id === activeProfile.id ? "active" : ""} ${profile.enabled ? "" : "disabled"}`}
          >
            <button
              className="policy-profile-main"
              onClick={() => setActiveProfileId(profile.id)}
            >
              <span>{profile.name.slice(0, 2).toUpperCase()}</span>
              <div>
                <small>{profile.environment}</small>
                <strong>{profile.name}</strong>
                <p>
                  {profile.configPath} · seuil {profile.failOn}
                </p>
              </div>
            </button>
            <label>
              <input
                type="checkbox"
                checked={profile.enabled}
                onChange={(event) =>
                  toggleProfile(profile.id, event.target.checked)
                }
              />
              Inclure
            </label>
          </article>
        ))}
      </div>

      <div className="ci-layout">
        <article className="module-card policy-builder">
          <div className="module-card-head">
            <div>
              <span className="section-kicker">
                POLITIQUE · {activeProfile.environment.toUpperCase()}
              </span>
              <h3>Configurer {activeProfile.name}</h3>
            </div>
          </div>
          <label>
            Nom affiché
            <input
              value={activeProfile.name}
              onChange={(event) =>
                updateActiveProfile({ name: event.target.value })
              }
              maxLength={60}
            />
          </label>
          <label>
            Chemin de la configuration
            <input
              value={activeProfile.configPath}
              onChange={(event) =>
                updateActiveProfile({ configPath: event.target.value })
              }
              maxLength={500}
            />
          </label>
          <label>
            Bloquer à partir de
            <select
              value={activeProfile.failOn}
              onChange={(event) =>
                updateActiveProfile({
                  failOn: event.target.value as Severity,
                })
              }
            >
              <option value="critical">Critique</option>
              <option value="high">Élevé</option>
              <option value="medium">Modéré</option>
            </select>
          </label>
          <div className="policy-checks">
            {([
              ["requireServers", "Exiger au moins un serveur"],
              ["provenance", "Vérifier signatures et provenance"],
              ["osv", "Interroger OSV pour les vulnérabilités"],
              ["sbom", "Produire un SBOM CycloneDX"],
              ["sarif", "Publier un rapport SARIF"],
            ] as const).map(([key, label]) => (
              <label key={key}>
                <input
                  type="checkbox"
                  checked={activeProfile[key]}
                  onChange={(event) =>
                    updateActiveProfile({ [key]: event.target.checked })
                  }
                />
                <span>
                  <strong>{label}</strong>
                  <small>
                    {key === "osv"
                      ? "Requête réseau explicite"
                      : "Activé dans le collecteur"}
                  </small>
                </span>
              </label>
            ))}
          </div>
          {generationError ? (
            <p className="form-error" role="alert">
              {generationError}
            </p>
          ) : null}
        </article>

        <article className="module-card workflow-card">
          <div className="module-card-head">
            <div>
              <span className="section-kicker">
                GITHUB ACTIONS · {enabledProfiles.length} POLITIQUE
                {enabledProfiles.length > 1 ? "S" : ""}
              </span>
              <h3>Workflow multi-environnements</h3>
            </div>
            <button
              className="text-button"
              disabled={Boolean(generationError)}
              onClick={() => copy(workflow, "Workflow")}
            >
              Copier
            </button>
          </div>
          <pre>
            <code>
              {workflow ||
                "# Corrigez la politique sélectionnée pour générer le workflow."}
            </code>
          </pre>
        </article>
      </div>

      <article className="command-card">
        <div>
          <span className="section-kicker">
            COMMANDE · {activeProfile.name.toUpperCase()}
          </span>
          <code>{command}</code>
        </div>
        <button
          className="button secondary"
          disabled={Boolean(generationError)}
          onClick={() => copy(command, "Commande CI")}
        >
          Copier
        </button>
      </article>

      <article className="module-card policy-signature-card">
        <div className="module-card-head">
          <div>
            <span className="section-kicker">CHAÎNE DE CONFIANCE</span>
            <h3>Signer et vérifier les politiques CI</h3>
          </div>
          <span className="crypto-badge">ECDSA P-256</span>
        </div>
        <p className="crypto-intro">
          La clé privée est exportée dans une identité chiffrée et ne quitte
          jamais votre navigateur en clair. Les destinataires approuvent la
          politique en comparant son empreinte par un canal séparé.
        </p>
        <div className="policy-trust-grid">
          <section>
            <span className="section-kicker">1 · IDENTITÉ ET SIGNATURE</span>
            <label>
              Nom du signataire
              <input
                value={signerLabel}
                maxLength={80}
                onChange={(event) => setSignerLabel(event.target.value)}
              />
            </label>
            <label>
              Phrase secrète de l’identité
              <input
                type="password"
                value={signingPassphrase}
                minLength={12}
                maxLength={256}
                autoComplete="new-password"
                onChange={(event) => setSigningPassphrase(event.target.value)}
                placeholder="12 caractères minimum"
              />
            </label>
            <label className="file-field">
              Identité chiffrée
              <input
                type="file"
                accept=".json,application/json"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  try {
                    setIdentityDocument(await readBoundedFile(file));
                    setIdentityFilename(file.name);
                    setSignatureError("");
                    setSignatureMessage("Identité chiffrée chargée localement.");
                  } catch (error) {
                    setSignatureError(
                      error instanceof Error
                        ? error.message
                        : "L’identité n’a pas pu être lue.",
                    );
                  } finally {
                    event.target.value = "";
                  }
                }}
              />
              <span>{identityFilename || "Aucun fichier chargé"}</span>
            </label>
            <div className="crypto-actions">
              <button
                className="button secondary"
                disabled={cryptoBusy}
                onClick={createIdentity}
              >
                Créer une identité
              </button>
              <button
                className="button primary"
                disabled={cryptoBusy || Boolean(generationError)}
                onClick={signPolicy}
              >
                Signer et exporter
              </button>
            </div>
          </section>
          <section>
            <span className="section-kicker">2 · VÉRIFICATION ET CHARGEMENT</span>
            <label className="file-field">
              Politique signée
              <input
                type="file"
                accept=".json,application/json"
                onChange={async (event) => {
                  const file = event.target.files?.[0];
                  if (!file) return;
                  try {
                    setPolicyDocument(await readBoundedFile(file));
                    setPolicyFilename(file.name);
                    setSignatureError("");
                    setSignatureMessage("Politique chargée, prête à vérifier.");
                  } catch (error) {
                    setSignatureError(
                      error instanceof Error
                        ? error.message
                        : "La politique n’a pas pu être lue.",
                    );
                  } finally {
                    event.target.value = "";
                  }
                }}
              />
              <span>{policyFilename || "Aucun fichier chargé"}</span>
            </label>
            <label>
              Empreinte approuvée
              <input
                value={expectedKeyId}
                maxLength={71}
                spellCheck={false}
                onChange={(event) =>
                  setExpectedKeyId(event.target.value.toLowerCase())
                }
                placeholder="sha256:…"
              />
            </label>
            <button
              className="button primary"
              disabled={cryptoBusy || !policyDocument}
              onClick={verifyPolicy}
            >
              Vérifier et charger
            </button>
          </section>
        </div>
        {observedKeyId ? (
          <div className="fingerprint">
            <span>Empreinte observée</span>
            <code>{observedKeyId}</code>
            <button
              className="text-button"
              onClick={() => copy(observedKeyId, "Empreinte")}
            >
              Copier
            </button>
          </div>
        ) : null}
        {signatureError ? (
          <p className="form-error" role="alert">
            {signatureError}
          </p>
        ) : null}
        {signatureMessage ? (
          <p className="crypto-message" role="status">
            {signatureMessage}
          </p>
        ) : null}
      </article>
    </section>
  );
}
