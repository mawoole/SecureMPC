import {
  compareAuditHistory,
  type AuditHistoryRecord,
  type AuditHistorySource,
} from "../lib/audit-history";

type AuditHistoryViewProps = {
  history: AuditHistoryRecord[];
  loading: boolean;
  error: string;
  onClear: () => void;
};

const sourceLabel: Record<AuditHistorySource, string> = {
  manual: "Audit relancé",
  import: "Configuration importée",
  discovery: "Inventaire découvert",
};

function historyDate(value: string, compact = false): string {
  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: compact ? "short" : "long",
    ...(compact ? {} : { hour: "2-digit", minute: "2-digit" }),
  }).format(new Date(value));
}

function signed(value: number, suffix = ""): string {
  return `${value > 0 ? "+" : ""}${value}${suffix}`;
}

export function AuditHistoryView({
  history,
  loading,
  error,
  onClear,
}: AuditHistoryViewProps) {
  const trend = [...history].slice(0, 12).reverse();
  const latest = history[0];
  const latestComparison = latest
    ? compareAuditHistory(latest, history[1])
    : undefined;

  if (loading) {
    return (
      <article className="history-empty" aria-live="polite">
        <span className="spin" aria-hidden="true">
          ◌
        </span>
        <strong>Chargement de l’historique sécurisé…</strong>
        <p>Les synthèses d’audit sont récupérées pour votre espace.</p>
      </article>
    );
  }

  if (!history.length) {
    return (
      <article className="history-empty" aria-live="polite">
        <span aria-hidden="true">↗</span>
        <strong>Aucun point de comparaison pour le moment</strong>
        <p>
          Importez un inventaire ou lancez un audit. Seuls les scores et
          compteurs de règles seront conservés, jamais les configurations.
        </p>
        {error ? <small>{error}</small> : null}
      </article>
    );
  }

  return (
    <>
      <div className="history-toolbar">
        <div>
          <span className={`history-sync ${error ? "warning" : ""}`}>
            <i aria-hidden="true" />
            {error || `${history.length} audit${history.length > 1 ? "s" : ""} conservé${history.length > 1 ? "s" : ""}`}
          </span>
          <small>
            Synthèses pseudonymisées · configurations exclues
          </small>
        </div>
        <button className="button secondary compact" onClick={onClear}>
          Effacer l’historique
        </button>
      </div>

      <div className="history-layout">
        <article className="trend-card">
          <div className="trend-head">
            <div>
              <span>Évolution du score</span>
              <strong
                className={
                  (latestComparison?.scoreDelta ?? 0) < 0 ? "negative" : ""
                }
              >
                {history.length > 1
                  ? signed(latestComparison?.scoreDelta ?? 0, " pts")
                  : "Premier point"}
              </strong>
            </div>
            <div className="trend-summary">
              <small>{history.length} points · 60 maximum</small>
              <b>{latest.score}/100 aujourd’hui</b>
            </div>
          </div>
          <div
            className="trend-visual"
            aria-label={`Tendance du score de ${trend[0].score} à ${latest.score}`}
          >
            {trend.map((entry, index) => (
              <span
                key={entry.id}
                style={{ height: `${Math.max(entry.score, 8)}%` }}
                title={`${historyDate(entry.createdAt)} · ${entry.score}/100`}
              >
                {index === trend.length - 1 ? <b>{entry.score}</b> : null}
              </span>
            ))}
          </div>
          <div className="trend-axis">
            <span>{historyDate(trend[0].createdAt, true)}</span>
            <span>{historyDate(latest.createdAt, true)}</span>
          </div>
          <div className="trend-deltas">
            <span>
              <small>Écarts ouverts</small>
              <strong
                className={
                  (latestComparison?.findingDelta ?? 0) > 0 ? "negative" : ""
                }
              >
                {history.length > 1
                  ? signed(latestComparison?.findingDelta ?? 0)
                  : latest.toFix}
              </strong>
            </span>
            <span>
              <small>Résolus depuis le précédent</small>
              <strong>{latestComparison?.resolvedFindings ?? 0}</strong>
            </span>
            <span>
              <small>Nouveaux depuis le précédent</small>
              <strong
                className={
                  (latestComparison?.introducedFindings ?? 0) > 0
                    ? "negative"
                    : ""
                }
              >
                {latestComparison?.introducedFindings ?? 0}
              </strong>
            </span>
          </div>
        </article>

        <div className="timeline-card">
          {history.slice(0, 8).map((entry, index) => {
            const comparison = compareAuditHistory(entry, history[index + 1]);
            const tone =
              entry.critical > 0
                ? "coral"
                : comparison.scoreDelta > 0
                  ? "green"
                  : comparison.scoreDelta < 0
                    ? "amber"
                    : "gray";
            return (
              <article className="timeline-entry" key={entry.id}>
                <span className={`timeline-dot ${tone}`} />
                <time dateTime={entry.createdAt}>
                  {historyDate(entry.createdAt, true)}
                </time>
                <div>
                  <strong>
                    {sourceLabel[entry.source]} · {entry.score}/100
                  </strong>
                  <p>
                    {entry.servers} serveur{entry.servers > 1 ? "s" : ""} ·{" "}
                    {entry.toFix} correction{entry.toFix > 1 ? "s" : ""} ouverte
                    {entry.toFix > 1 ? "s" : ""}
                  </p>
                  {index < history.length - 1 ? (
                    <small>
                      {comparison.resolvedFindings} résolu
                      {comparison.resolvedFindings > 1 ? "s" : ""} ·{" "}
                      {comparison.introducedFindings} nouveau
                      {comparison.introducedFindings === 1 ? "" : "x"}
                    </small>
                  ) : null}
                </div>
              </article>
            );
          })}
        </div>
      </div>
    </>
  );
}
