"use client";

import { useMemo, useState } from "react";
import type { McpServer, Severity } from "../lib/audit-engine";
import type { RiskException } from "../lib/finding-exceptions";
import {
  createCiCommand,
  createGithubActionsWorkflow,
  evaluateCiGate,
  type TrustMapCiOptions,
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
  const [options, setOptions] = useState<TrustMapCiOptions>({
    configPath: "./.mcp.json",
    failOn: "high",
    sarif: true,
    sbom: true,
    osv: false,
    provenance: true,
    requireServers: true,
  });
  const command = useMemo(() => createCiCommand(options), [options]);
  const workflow = useMemo(() => createGithubActionsWorkflow(options), [options]);
  const gate = useMemo(
    () => evaluateCiGate(servers, exceptions, options.failOn),
    [exceptions, options.failOn, servers],
  );

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
            Configurez un seuil, générez un workflow GitHub Actions et publiez
            les écarts dans Code Scanning avec un rapport SARIF.
          </p>
        </div>
        <div className={`gate-preview ${gate.passed ? "passed" : "blocked"}`}>
          <span>{gate.passed ? "✓" : "!"}</span>
          <div><small>SIMULATION SUR L’INVENTAIRE</small><strong>{gate.passed ? "Livraison autorisée" : "Livraison bloquée"}</strong><p>{gate.label}</p></div>
        </div>
      </div>

      <div className="ci-layout">
        <article className="module-card policy-builder">
          <div className="module-card-head"><div><span className="section-kicker">POLITIQUE</span><h3>Composer le contrôle</h3></div></div>
          <label>
            Chemin de la configuration
            <input value={options.configPath} onChange={(event) => setOptions({ ...options, configPath: event.target.value })} />
          </label>
          <label>
            Bloquer à partir de
            <select value={options.failOn} onChange={(event) => setOptions({ ...options, failOn: event.target.value as Severity })}>
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
                <input type="checkbox" checked={options[key]} onChange={(event) => setOptions({ ...options, [key]: event.target.checked })} />
                <span><strong>{label}</strong><small>{key === "osv" ? "Requête réseau explicite" : "Activé dans le collecteur"}</small></span>
              </label>
            ))}
          </div>
        </article>

        <article className="module-card workflow-card">
          <div className="module-card-head">
            <div><span className="section-kicker">GITHUB ACTIONS</span><h3>Workflow prêt à versionner</h3></div>
            <button className="text-button" onClick={() => copy(workflow, "Workflow")}>Copier</button>
          </div>
          <pre><code>{workflow}</code></pre>
        </article>
      </div>

      <article className="command-card">
        <div><span className="section-kicker">COMMANDE ÉQUIVALENTE</span><code>{command}</code></div>
        <button className="button secondary" onClick={() => copy(command, "Commande CI")}>Copier</button>
      </article>
    </section>
  );
}
