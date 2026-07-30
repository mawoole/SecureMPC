"use client";

import { useMemo } from "react";
import type { McpServer } from "../lib/audit-engine";
import type { RiskException } from "../lib/finding-exceptions";
import {
  createEnterprisePolicyPack,
  createEnterpriseSummary,
} from "../lib/trustmap-modules";

export function TrustMapEnterprise({
  servers,
  exceptions,
  onNotify,
}: {
  servers: McpServer[];
  exceptions: RiskException[];
  onNotify: (message: string) => void;
}) {
  const summary = useMemo(
    () => createEnterpriseSummary(servers, exceptions),
    [exceptions, servers],
  );

  const exportPolicyPack = () => {
    const payload = JSON.stringify(
      createEnterprisePolicyPack(servers, exceptions),
      null,
      2,
    );
    const url = URL.createObjectURL(
      new Blob([payload], { type: "application/json" }),
    );
    const link = document.createElement("a");
    link.href = url;
    link.download = `mcp-trustmap-governance-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(url);
    onNotify("Pack de gouvernance Enterprise exporté");
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
      <p className="enterprise-note">
        Les fonctions multi-utilisateurs, SSO et synchronisation d’exceptions
        nécessitent un service d’identité et ne sont pas simulées dans cette version.
      </p>
    </section>
  );
}
