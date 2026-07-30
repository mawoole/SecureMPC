import type { McpServer } from "../lib/audit-engine";
import { createDiscoverSummary } from "../lib/trustmap-modules";

export function TrustMapDiscover({
  servers,
  onDiscover,
  onImport,
  onSelect,
}: {
  servers: McpServer[];
  onDiscover: () => void;
  onImport: () => void;
  onSelect: (server: McpServer) => void;
}) {
  const summary = createDiscoverSummary(servers);

  return (
    <section className="module-view discover-view">
      <div className="module-hero">
        <div>
          <span className="module-badge">TRUSTMAP DISCOVER</span>
          <h2>Cartographiez chaque serveur MCP avant qu’il ne devienne une zone d’ombre.</h2>
          <p>
            Regroupez les configurations locales, les transports et les composants
            logiciels dans un inventaire unique, sans exécuter les serveurs stdio.
          </p>
        </div>
        <div className="module-actions">
          <button className="button primary" onClick={onDiscover}>
            Lancer la découverte
          </button>
          <button className="button secondary" onClick={onImport}>
            Importer un inventaire
          </button>
        </div>
      </div>

      <div className="module-kpis">
        <article><span>Serveurs découverts</span><strong>{summary.servers}</strong><small>{summary.sources.length} source{summary.sources.length > 1 ? "s" : ""}</small></article>
        <article><span>Composants suivis</span><strong>{summary.components}</strong><small>{summary.pinnedComponents} verrouillés</small></article>
        <article><span>Preuves vérifiées</span><strong>{summary.provenanceVerified}</strong><small>Signature ou SLSA</small></article>
        <article><span>Transports</span><strong>{summary.transports.length}</strong><small>stdio, HTTPS et autres</small></article>
      </div>

      <div className="module-grid">
        <article className="module-card">
          <div className="module-card-head">
            <div><span className="section-kicker">ORIGINE</span><h3>Sources détectées</h3></div>
            <span className="count-badge">{summary.sources.length}</span>
          </div>
          <div className="distribution-list">
            {summary.sources.map((source) => (
              <div key={source.label}>
                <span><strong>{source.label}</strong><small>{source.count} serveur{source.count > 1 ? "s" : ""}</small></span>
                <i><b style={{ width: `${source.percentage}%` }} /></i>
                <em>{source.percentage}%</em>
              </div>
            ))}
          </div>
        </article>
        <article className="module-card">
          <div className="module-card-head">
            <div><span className="section-kicker">SURFACE</span><h3>Transports exposés</h3></div>
          </div>
          <div className="transport-grid">
            {summary.transports.map((transport) => (
              <div key={transport.label}>
                <span aria-hidden="true">{transport.label.toLowerCase().includes("https") ? "↗" : "⌘"}</span>
                <strong>{transport.label}</strong>
                <small>{transport.count} serveur{transport.count > 1 ? "s" : ""}</small>
              </div>
            ))}
          </div>
        </article>
      </div>

      <article className="module-card inventory-card">
        <div className="module-card-head">
          <div><span className="section-kicker">INVENTAIRE ACTUEL</span><h3>Carte des serveurs</h3></div>
          <small>Sélectionnez un serveur pour ouvrir ses preuves</small>
        </div>
        <div className="inventory-list">
          {servers.map((server) => (
            <button key={server.id} onClick={() => onSelect(server)}>
              <span className={`server-icon ${server.status}`}>{server.name.slice(0, 2).toUpperCase()}</span>
              <span><strong>{server.name}</strong><small>{server.source} · {server.transport}</small></span>
              <span><strong>{server.components?.length ?? 0}</strong><small>composants</small></span>
              <span className={`inventory-status ${server.status}`}>{server.score}/100</span>
              <b aria-hidden="true">→</b>
            </button>
          ))}
        </div>
      </article>
    </section>
  );
}
