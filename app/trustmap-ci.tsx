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
    </section>
  );
}
