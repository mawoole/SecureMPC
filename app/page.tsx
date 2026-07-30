"use client";

import {
  ChangeEvent,
  CSSProperties,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  auditConfiguration,
  calculateAuditMetrics,
  SECURITY_RULES,
  type Finding,
  type McpServer,
  type ProbeStatus,
  type ServerStatus,
  type Severity,
} from "../lib/audit-engine";
import {
  createGovernedAuditReport,
  createGovernedSarifReport,
  createRiskException,
  findActiveRiskException,
  findLatestRiskException,
  findingExceptionKey,
  openFindingEntries,
  parseRiskExceptions,
  revokeRiskException,
  riskExceptionStatus,
  type RiskException,
} from "../lib/finding-exceptions";
import {
  createCycloneDxReport,
  type ComponentPinStatus,
} from "../lib/supply-chain";

type View = "overview" | "servers" | "rules" | "history";

type ExceptionDraft = {
  findingKey: string;
  reason: string;
  owner: string;
  expiresOn: string;
  minimumExpiresOn: string;
  maximumExpiresOn: string;
};

const RISK_EXCEPTIONS_STORAGE_KEY = "mcp-sentinel.risk-exceptions.v1";

function dateInputValue(date: Date): string {
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 10);
}

function defaultExceptionExpiry(): string {
  return dateInputValue(new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000));
}

function formatExceptionDate(value: string): string {
  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: "short",
    year: "numeric",
  }).format(new Date(value));
}

const severityLabel: Record<Severity, string> = {
  critical: "Critique",
  high: "Élevé",
  medium: "Modéré",
};

const statusLabel: Record<ServerStatus, string> = {
  critical: "Critique",
  attention: "À corriger",
  secure: "Conforme",
};

const probeStatusLabel: Record<ProbeStatus, string> = {
  "not-requested": "Non vérifié",
  reachable: "Négociation réussie",
  "auth-required": "Authentification exigée",
  "skipped-insecure": "Ignoré — HTTP non chiffré",
  "skipped-stdio": "Ignoré — exécution locale",
  timeout: "Délai dépassé",
  unreachable: "Injoignable",
  "protocol-error": "Erreur de protocole",
};

const pinStatusLabel: Record<ComponentPinStatus, string> = {
  pinned: "Immuable",
  unpinned: "Non verrouillé",
  mutable: "Tag mutable",
  unknown: "Version inconnue",
  "not-applicable": "Non applicable",
};

const makeFinding = (
  id: string,
  severity: Severity,
  title: string,
  description: string,
  remediation: string,
  snippet: string,
  rule: string,
): Finding => ({
  id,
  severity,
  title,
  description,
  remediation,
  snippet,
  rule,
});

const demoServers: McpServer[] = [
  {
    id: "github",
    name: "GitHub MCP",
    owner: "Équipe Platform",
    transport: "Stdio",
    source: "Claude Desktop",
    score: 42,
    status: "critical",
    controls: 4,
    lastScan: "il y a 2 min",
    findings: [
      makeFinding(
        "github-secret",
        "critical",
        "Secret stocké dans la configuration",
        "Un jeton d’accès est présent directement dans le bloc env. Il peut fuiter via une sauvegarde, un log ou un partage de configuration.",
        "Placez le jeton dans un coffre de secrets, injectez-le au démarrage et révoquez la valeur actuellement exposée.",
        `"env": {\n  "GITHUB_TOKEN": "\${GITHUB_TOKEN}"\n}`,
        "MCP-SEC-01",
      ),
      makeFinding(
        "github-version",
        "high",
        "Dépendance non verrouillée",
        "Le serveur est lancé avec npx sans version exacte. Une mise à jour compromise pourrait être exécutée automatiquement.",
        "Verrouillez le paquet sur une version revue et mettez les mises à jour sous contrôle de votre gestionnaire de dépendances.",
        `"args": ["-y", "@modelcontextprotocol/server-github@2026.7.2"]`,
        "MCP-SUP-02",
      ),
    ],
  },
  {
    id: "filesystem",
    name: "Filesystem MCP",
    owner: "Équipe Produit",
    transport: "Stdio",
    source: "Cursor",
    score: 58,
    status: "critical",
    controls: 4,
    lastScan: "il y a 2 min",
    findings: [
      makeFinding(
        "fs-scope",
        "critical",
        "Périmètre de fichiers trop large",
        "Le serveur peut parcourir la racine du disque. Une instruction malveillante pourrait lire des clés, des sources ou des fichiers personnels.",
        "Exposez uniquement le dossier nécessaire au projet et exécutez le processus avec un compte sans privilèges.",
        `"args": [\n  "@modelcontextprotocol/server-filesystem@2026.7.1",\n  "/workspace/projet-mcp"\n]`,
        "MCP-AUTHZ-03",
      ),
    ],
  },
  {
    id: "postgres",
    name: "Postgres Ops",
    owner: "Équipe Data",
    transport: "Stdio",
    source: "VS Code",
    score: 67,
    status: "critical",
    controls: 4,
    lastScan: "il y a 4 min",
    findings: [
      makeFinding(
        "pg-role",
        "critical",
        "Compte de base de données sur-privilégié",
        "La connexion utilise un rôle administrateur avec des droits d’écriture sur la production.",
        "Créez un rôle dédié en lecture seule, limitez-le au schéma utile et imposez une durée maximale aux requêtes.",
        `CREATE ROLE mcp_reader LOGIN;\nGRANT CONNECT ON DATABASE ops TO mcp_reader;\nGRANT USAGE ON SCHEMA reporting TO mcp_reader;\nGRANT SELECT ON ALL TABLES IN SCHEMA reporting TO mcp_reader;`,
        "MCP-AUTHZ-01",
      ),
    ],
  },
  {
    id: "notion",
    name: "Notion Knowledge",
    owner: "Équipe Enablement",
    transport: "HTTPS",
    source: "Claude Desktop",
    score: 76,
    status: "secure",
    controls: 4,
    lastScan: "il y a 5 min",
    findings: [],
  },
  {
    id: "slack",
    name: "Slack Gateway",
    owner: "Équipe Support",
    transport: "HTTPS",
    source: "Configuration centrale",
    score: 91,
    status: "attention",
    controls: 4,
    lastScan: "il y a 7 min",
    findings: [
      makeFinding(
        "slack-scope",
        "high",
        "Portée OAuth excessive",
        "Le jeton peut écrire dans tous les canaux alors que ce serveur n’effectue que de la recherche.",
        "Remplacez les droits d’écriture par les seules portées de lecture nécessaires, puis renouvelez le jeton.",
        `scopes:\n  - channels:read\n  - search:read\n  - users:read`,
        "MCP-AUTHZ-02",
      ),
    ],
  },
  {
    id: "browser",
    name: "Browser Tools",
    owner: "Équipe QA",
    transport: "Stdio",
    source: "Cursor",
    score: 82,
    status: "critical",
    controls: 4,
    lastScan: "il y a 8 min",
    findings: [
      makeFinding(
        "browser-flag",
        "critical",
        "Contournement de sécurité activé",
        "Le paramètre --no-sandbox désactive une barrière d’isolation essentielle du navigateur.",
        "Supprimez ce paramètre et exécutez le navigateur dans un conteneur ou un profil isolé et éphémère.",
        `"args": ["@acme/browser-mcp@3.4.1", "--isolated", "--ephemeral"]`,
        "MCP-EXEC-02",
      ),
    ],
  },
  {
    id: "sentry",
    name: "Sentry Reader",
    owner: "Équipe SRE",
    transport: "HTTPS",
    source: "Configuration centrale",
    score: 88,
    status: "secure",
    controls: 4,
    lastScan: "il y a 10 min",
    findings: [],
  },
  {
    id: "fetch",
    name: "Internal Fetch",
    owner: "Équipe Platform",
    transport: "HTTP",
    source: "VS Code",
    score: 52,
    status: "critical",
    controls: 4,
    lastScan: "il y a 11 min",
    findings: [
      makeFinding(
        "fetch-tls",
        "critical",
        "Transport non chiffré",
        "Le serveur distant utilise HTTP. Les requêtes, réponses et éventuels jetons peuvent être interceptés.",
        "Exposez le serveur uniquement en HTTPS avec un certificat valide et refusez toute redirection vers HTTP.",
        `"url": "https://mcp.internal.example/v1"\n"transport": "streamable-http"`,
        "MCP-NET-01",
      ),
    ],
  },
  {
    id: "kubernetes",
    name: "Kubernetes Prod",
    owner: "Équipe SRE",
    transport: "Stdio",
    source: "Claude Desktop",
    score: 73,
    status: "critical",
    controls: 4,
    lastScan: "il y a 12 min",
    findings: [
      makeFinding(
        "k8s-shell",
        "critical",
        "Exécution via un interpréteur de commandes",
        "Le serveur démarre avec bash -c, ce qui augmente le risque d’injection de commandes par les arguments ou variables.",
        "Lancez directement le binaire MCP et appliquez un profil RBAC Kubernetes limité aux ressources consultées.",
        `"command": "/opt/mcp/kubernetes-server"\n"args": ["--context", "prod-readonly"]`,
        "MCP-EXEC-01",
      ),
    ],
  },
  {
    id: "linear",
    name: "Linear MCP",
    owner: "Équipe Produit",
    transport: "HTTPS",
    source: "Configuration centrale",
    score: 96,
    status: "secure",
    controls: 4,
    lastScan: "il y a 15 min",
    findings: [],
  },
  {
    id: "analytics",
    name: "Analytics DB",
    owner: "Équipe Data",
    transport: "Stdio",
    source: "Cursor",
    score: 65,
    status: "attention",
    controls: 4,
    lastScan: "il y a 17 min",
    findings: [
      makeFinding(
        "analytics-audit",
        "medium",
        "Journalisation insuffisante",
        "Aucun identifiant de session MCP n’est transmis aux journaux de requêtes de la base.",
        "Ajoutez un nom d’application et corrélez chaque appel d’outil à l’identité de l’utilisateur et à la session.",
        `PGAPPNAME=mcp-analytics\nMCP_AUDIT_MODE=metadata-only`,
        "MCP-AUDIT-01",
      ),
    ],
  },
  {
    id: "design",
    name: "Design Assets",
    owner: "Équipe Design",
    transport: "HTTPS",
    source: "Configuration centrale",
    score: 74,
    status: "secure",
    controls: 3,
    lastScan: "il y a 19 min",
    findings: [],
  },
];

const rules = SECURITY_RULES;

const sampleConfig = `{
  "mcpServers": {
    "filesystem-project": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"]
    },
    "internal-api": {
      "url": "http://mcp.internal.example/v1",
      "headers": {
        "Authorization": "Bearer secret-token-value"
      }
    }
  }
}`;

function BrandMark() {
  return (
    <span className="brand-mark" aria-hidden="true">
      M
    </span>
  );
}

function StatusDot({ status }: { status: ServerStatus }) {
  return <span className={`status-dot ${status}`} aria-hidden="true" />;
}

export default function Home() {
  const [servers, setServers] = useState<McpServer[]>(demoServers);
  const [view, setView] = useState<View>("overview");
  const [filter, setFilter] = useState<"all" | ServerStatus>("all");
  const [search, setSearch] = useState("");
  const [selectedServer, setSelectedServer] = useState<McpServer | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [discoveryOpen, setDiscoveryOpen] = useState(false);
  const [configText, setConfigText] = useState(sampleConfig);
  const [importError, setImportError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState("");
  const [lastAudit, setLastAudit] = useState("Aujourd’hui, 14:32");
  const [riskExceptions, setRiskExceptions] = useState<RiskException[]>([]);
  const [exceptionsLoaded, setExceptionsLoaded] = useState(false);
  const [exceptionDraft, setExceptionDraft] =
    useState<ExceptionDraft | null>(null);
  const [exceptionError, setExceptionError] = useState("");

  useEffect(() => {
    const loadTimer = window.setTimeout(() => {
      setRiskExceptions(
        parseRiskExceptions(
          window.localStorage.getItem(RISK_EXCEPTIONS_STORAGE_KEY),
        ),
      );
      setExceptionsLoaded(true);
    }, 0);
    return () => window.clearTimeout(loadTimer);
  }, []);

  useEffect(() => {
    if (!exceptionsLoaded) return;
    try {
      window.localStorage.setItem(
        RISK_EXCEPTIONS_STORAGE_KEY,
        JSON.stringify(riskExceptions),
      );
    } catch {
      const errorTimer = window.setTimeout(
        () =>
          setToast(
            "Le registre d’exceptions n’a pas pu être enregistré sur cet appareil.",
          ),
        0,
      );
      return () => window.clearTimeout(errorTimer);
    }
  }, [exceptionsLoaded, riskExceptions]);

  const metrics = useMemo(() => calculateAuditMetrics(servers), [servers]);
  const actionableFindings = useMemo(
    () => openFindingEntries(servers, riskExceptions),
    [riskExceptions, servers],
  );
  const actionableCritical = useMemo(
    () =>
      actionableFindings.filter(
        ({ finding }) => finding.severity === "critical",
      ).length,
    [actionableFindings],
  );
  const activeExceptionCount = useMemo(
    () =>
      riskExceptions.filter(
        (exception) => riskExceptionStatus(exception) === "active",
      ).length,
    [riskExceptions],
  );
  const exceptionRegister = useMemo(
    () =>
      riskExceptions
        .map((exception) => ({
          exception,
          status: riskExceptionStatus(exception),
        }))
        .sort(
          (left, right) =>
            Date.parse(right.exception.createdAt) -
            Date.parse(left.exception.createdAt),
        ),
    [riskExceptions],
  );

  const filteredServers = useMemo(() => {
    const normalizedSearch = search.trim().toLowerCase();
    return servers.filter(
      (server) =>
        (filter === "all" || server.status === filter) &&
        (!normalizedSearch ||
          server.name.toLowerCase().includes(normalizedSearch) ||
          server.owner.toLowerCase().includes(normalizedSearch)),
    );
  }, [filter, search, servers]);

  const priorityFindings = useMemo(
    () =>
      [...actionableFindings]
        .sort((a, b) => {
          const order: Record<Severity, number> = {
            critical: 0,
            high: 1,
            medium: 2,
          };
          return order[a.finding.severity] - order[b.finding.severity];
        }),
    [actionableFindings],
  );

  const runAudit = () => {
    setScanning(true);
    window.setTimeout(() => {
      setScanning(false);
      setLastAudit(
        new Intl.DateTimeFormat("fr-FR", {
          hour: "2-digit",
          minute: "2-digit",
        }).format(new Date()),
      );
      setToast(`${servers.length} serveurs analysés — rapport actualisé`);
      window.setTimeout(() => setToast(""), 3000);
    }, 950);
  };

  const applyAuditedServers = (audited: McpServer[], source: string) => {
    if (!audited.length) {
      throw new Error("La configuration ne contient aucun serveur.");
    }
    setServers(audited);
    setImportOpen(false);
    setDiscoveryOpen(false);
    setFilter("all");
    setSearch("");
    setLastAudit("à l’instant");
    setToast(
      `${audited.length} serveur${audited.length > 1 ? "s" : ""} ${source} et analysé${audited.length > 1 ? "s" : ""} localement`,
    );
    window.setTimeout(() => setToast(""), 3500);
  };

  const importConfiguration = () => {
    setImportError("");
    try {
      const audited = auditConfiguration(configText);
      applyAuditedServers(
        audited,
        `importé${audited.length > 1 ? "s" : ""}`,
      );
    } catch (error) {
      setImportError(
        error instanceof Error
          ? error.message
          : "Cette configuration JSON n’est pas valide.",
      );
    }
  };

  const handleFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    if (file.size > 1_000_000) {
      setImportError("Le fichier dépasse la limite de 1 Mo.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setConfigText(String(reader.result ?? ""));
      setImportError("");
    };
    reader.onerror = () =>
      setImportError("Le fichier n’a pas pu être lu localement.");
    reader.readAsText(file);
  };

  const handleInventoryFile = async (
    event: ChangeEvent<HTMLInputElement>,
  ) => {
    const file = event.target.files?.[0];
    if (!file) return;
    setImportError("");
    if (file.size > 5_000_000) {
      setImportError("L’inventaire dépasse la limite de 5 Mo.");
      return;
    }

    try {
      const audited = auditConfiguration(await file.text());
      applyAuditedServers(
        audited,
        `découvert${audited.length > 1 ? "s" : ""}`,
      );
    } catch (error) {
      setImportError(
        error instanceof Error
          ? error.message
          : "Cet inventaire JSON n’est pas valide.",
      );
    } finally {
      event.target.value = "";
    }
  };

  const copyCollectorCommand = async () => {
    await navigator.clipboard.writeText("npm run collect:security");
    setToast("Commande du collecteur copiée");
    window.setTimeout(() => setToast(""), 2200);
  };

  const copySnippet = async (finding: Finding) => {
    await navigator.clipboard.writeText(finding.snippet);
    setToast("Correctif copié dans le presse-papiers");
    window.setTimeout(() => setToast(""), 2200);
  };

  const openExceptionForm = (server: McpServer, finding: Finding) => {
    const openedAt = new Date();
    setExceptionDraft({
      findingKey: findingExceptionKey(server, finding),
      reason: "",
      owner: server.owner === "Non attribué" ? "" : server.owner,
      expiresOn: defaultExceptionExpiry(),
      minimumExpiresOn: dateInputValue(
        new Date(openedAt.getTime() + 24 * 60 * 60 * 1_000),
      ),
      maximumExpiresOn: dateInputValue(
        new Date(openedAt.getTime() + 366 * 24 * 60 * 60 * 1_000),
      ),
    });
    setExceptionError("");
  };

  const saveRiskException = (server: McpServer, finding: Finding) => {
    if (!exceptionDraft) return;
    setExceptionError("");

    if (findActiveRiskException(server, finding, riskExceptions)) {
      setExceptionError("Une exception active existe déjà pour cet écart.");
      return;
    }

    try {
      const expiration = new Date(
        `${exceptionDraft.expiresOn}T23:59:59.999`,
      );
      const created = createRiskException({
        id: window.crypto.randomUUID(),
        server,
        finding,
        reason: exceptionDraft.reason,
        owner: exceptionDraft.owner,
        expiresAt: expiration.toISOString(),
      });
      setRiskExceptions((current) => [...current, created]);
      setExceptionDraft(null);
      setToast(
        `Exception documentée jusqu’au ${formatExceptionDate(created.expiresAt)}`,
      );
      window.setTimeout(() => setToast(""), 3000);
    } catch (error) {
      setExceptionError(
        error instanceof Error
          ? error.message
          : "L’exception n’a pas pu être enregistrée.",
      );
    }
  };

  const revokeException = (exceptionId: string) => {
    setRiskExceptions((current) =>
      current.map((exception) =>
        exception.id === exceptionId
          ? revokeRiskException(exception)
          : exception,
      ),
    );
    setExceptionDraft(null);
    setExceptionError("");
    setToast("Exception révoquée — l’écart redevient prioritaire");
    window.setTimeout(() => setToast(""), 3000);
  };

  const exportReport = async (
    format: "json" | "sarif" | "cyclonedx" | "pdf",
  ) => {
    const generatedAt = new Date();
    try {
      let blob: Blob;
      let fileName: string;
      let successMessage: string;

      if (format === "pdf") {
        setToast("Génération locale du rapport PDF…");
        const { createAuditPdfReport } = await import("../lib/pdf-report");
        const report = createAuditPdfReport(
          servers,
          riskExceptions,
          generatedAt,
        );
        const pdfBuffer = report.bytes.buffer.slice(
          report.bytes.byteOffset,
          report.bytes.byteOffset + report.bytes.byteLength,
        ) as ArrayBuffer;
        blob = new Blob([pdfBuffer], { type: "application/pdf" });
        fileName = report.fileName;
        successMessage = `Rapport PDF exporté · ${report.pages} page${report.pages > 1 ? "s" : ""}`;
      } else {
        const report =
          format === "sarif"
            ? createGovernedSarifReport(servers, riskExceptions, generatedAt)
            : format === "cyclonedx"
              ? createCycloneDxReport(servers, generatedAt)
              : createGovernedAuditReport(
                  servers,
                  riskExceptions,
                  generatedAt,
                );
        const content = JSON.stringify(report, null, 2);
        blob = new Blob([content], {
          type:
            format === "sarif"
              ? "application/sarif+json"
              : format === "cyclonedx"
                ? "application/vnd.cyclonedx+json"
                : "application/json",
        });
        const date = generatedAt.toISOString().slice(0, 10);
        fileName =
          format === "cyclonedx"
            ? `mcp-sentinel-${date}.cdx.json`
            : `mcp-sentinel-${date}.${format}`;
        successMessage =
          format === "sarif"
            ? "Rapport SARIF exporté"
            : format === "cyclonedx"
              ? "SBOM CycloneDX exporté"
              : "Rapport JSON exporté";
      }

      const downloadUrl = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = downloadUrl;
      link.download = fileName;
      link.click();
      URL.revokeObjectURL(downloadUrl);
      setToast(successMessage);
      window.setTimeout(() => setToast(""), 2600);
    } catch {
      setToast("Le rapport n’a pas pu être généré sur cet appareil.");
      window.setTimeout(() => setToast(""), 3500);
    } finally {
      document
        .querySelector<HTMLDetailsElement>(".export-menu[open]")
        ?.removeAttribute("open");
    }
  };

  const navItems: { id: View; label: string; icon: string }[] = [
    { id: "overview", label: "Vue d’ensemble", icon: "⌂" },
    { id: "servers", label: "Serveurs", icon: "▦" },
    { id: "rules", label: "Règles de sécurité", icon: "✓" },
    { id: "history", label: "Historique", icon: "↗" },
  ];

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark />
          <div>
            <strong>MCP Sentinel</strong>
            <span>Security workspace</span>
          </div>
        </div>

        <nav className="nav" aria-label="Navigation principale">
          <span className="nav-label">SURVEILLANCE</span>
          {navItems.map((item) => (
            <button
              className={view === item.id ? "active" : ""}
              key={item.id}
              onClick={() => setView(item.id)}
            >
              <span aria-hidden="true">{item.icon}</span>
              {item.label}
              {item.id === "servers" && (
                <small>{servers.length}</small>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-foot">
          <div className="coverage">
            <div className="coverage-heading">
              <span>Couverture</span>
              <strong>
                {metrics.controls ? "100%" : "0%"}
              </strong>
            </div>
            <div className="coverage-bar">
              <span />
            </div>
            <p>{metrics.controls} contrôles exécutés sur le parc actuel.</p>
          </div>
          <button className="profile-button">
            <span className="avatar">GD</span>
            <span>
              <strong>Workspace sécurité</strong>
              <small>Administrateur</small>
            </span>
            <span aria-hidden="true">•••</span>
          </button>
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div>
            <p className="eyebrow">ESPACE DE TRAVAIL / PRODUCTION</p>
            <h1>
              {view === "overview" && "Vue d’ensemble"}
              {view === "servers" && "Serveurs MCP"}
              {view === "rules" && "Règles de sécurité"}
              {view === "history" && "Historique des audits"}
            </h1>
          </div>
          <div className="topbar-actions">
            <span className="last-scan">
              <i aria-hidden="true" />
              Dernier audit : {lastAudit}
            </span>
            <details className="export-menu">
              <summary className="button secondary">
                <span aria-hidden="true">↓</span>
                Exporter
              </summary>
              <div className="export-options">
                <button onClick={() => exportReport("pdf")}>
                  <span aria-hidden="true">▤</span>
                  <span>
                    <strong>Rapport PDF</strong>
                    <small>Synthèse, risques et corrections</small>
                  </span>
                </button>
                <button onClick={() => exportReport("json")}>
                  <span aria-hidden="true">{`{ }`}</span>
                  <span>
                    <strong>Rapport JSON</strong>
                    <small>Inventaire complet et remédiations</small>
                  </span>
                </button>
                <button onClick={() => exportReport("sarif")}>
                  <span aria-hidden="true">◇</span>
                  <span>
                    <strong>Rapport SARIF</strong>
                    <small>Compatible avec les outils de sécurité</small>
                  </span>
                </button>
                <button onClick={() => exportReport("cyclonedx")}>
                  <span aria-hidden="true">⬡</span>
                  <span>
                    <strong>SBOM CycloneDX</strong>
                    <small>Composants npm, PyPI et images OCI</small>
                  </span>
                </button>
              </div>
            </details>
            <button
              className="button secondary"
              onClick={() => {
                setImportError("");
                setDiscoveryOpen(true);
              }}
            >
              <span aria-hidden="true">◎</span>
              Découvrir
            </button>
            <button
              className="button secondary"
              onClick={() => {
                setImportError("");
                setImportOpen(true);
              }}
            >
              <span aria-hidden="true">＋</span>
              Importer
            </button>
            <button
              className="button primary"
              onClick={runAudit}
              disabled={scanning}
            >
              <span className={scanning ? "spin" : ""} aria-hidden="true">
                ↻
              </span>
              {scanning ? "Analyse…" : "Lancer un audit"}
            </button>
          </div>
        </header>

        {view === "overview" && (
          <>
            <section className="hero-grid" aria-label="Indicateurs de sécurité">
              <article className="score-card">
                <div className="score-copy">
                  <div>
                    <span className="section-kicker">POSTURE GLOBALE</span>
                    <h2>
                      Votre parc mérite
                      <br />
                      encore quelques corrections.
                    </h2>
                  </div>
                  <p>
                    {actionableCritical
                      ? `${actionableCritical} risques critiques nécessitent une action immédiate.`
                      : "Aucun risque critique sans exception active sur la configuration actuelle."}
                  </p>
                </div>
                <div
                  className="score-ring"
                  style={
                    {
                      "--score": `${metrics.score * 3.6}deg`,
                    } as CSSProperties
                  }
                >
                  <div>
                    <strong>{metrics.score}</strong>
                    <span>/ 100</span>
                  </div>
                </div>
              </article>

              <div className="metric-stack">
                <article className="metric-card">
                  <div className="metric-icon cobalt" aria-hidden="true">
                    ▦
                  </div>
                  <div>
                    <span>Serveurs suivis</span>
                    <strong>{servers.length}</strong>
                  </div>
                  <small>{metrics.secure} conformes</small>
                </article>
                <article className="metric-card">
                  <div className="metric-icon green" aria-hidden="true">
                    ✓
                  </div>
                  <div>
                    <span>Contrôles exécutés</span>
                    <strong>{metrics.controls}</strong>
                  </div>
                  <small>Référentiel v1.3</small>
                </article>
                <article className="metric-card danger-card">
                  <div className="metric-icon coral" aria-hidden="true">
                    !
                  </div>
                  <div>
                    <span>Risques critiques</span>
                    <strong>{actionableCritical}</strong>
                  </div>
                  <small>
                    {activeExceptionCount
                      ? `${activeExceptionCount} sous exception`
                      : "Action immédiate"}
                  </small>
                </article>
              </div>
            </section>

            <section className="workspace-grid">
              <ServerPanel
                servers={filteredServers.slice(0, 6)}
                total={servers.length}
                filter={filter}
                setFilter={setFilter}
                search={search}
                setSearch={setSearch}
                onSelect={setSelectedServer}
                onSeeAll={() => setView("servers")}
              />
              <RemediationPanel
                items={priorityFindings.slice(0, 4)}
                total={actionableFindings.length}
                onSelect={(server, finding) => {
                  setSelectedServer(server);
                  setSelectedFinding(finding);
                }}
              />
            </section>

            <section className="privacy-note">
              <div className="privacy-icon" aria-hidden="true">
                ✓
              </div>
              <div>
                <strong>Analyse locale et respectueuse de vos secrets</strong>
                <p>
                  Les configurations importées sont analysées dans votre
                  navigateur. MCP Sentinel n’affiche jamais les valeurs
                  sensibles détectées.
                </p>
              </div>
              <span>STATIQUE · SANS ENVOI</span>
            </section>
          </>
        )}

        {view === "servers" && (
          <section className="single-view">
            <div className="view-intro">
              <div>
                <span className="section-kicker">INVENTAIRE</span>
                <h2>Tous vos serveurs, une posture lisible.</h2>
                <p>
                  Triez le parc par urgence et ouvrez chaque serveur pour
                  appliquer les correctifs recommandés.
                </p>
              </div>
              <div className="legend">
                <span>
                  <StatusDot status="secure" /> Conforme
                </span>
                <span>
                  <StatusDot status="attention" /> À corriger
                </span>
                <span>
                  <StatusDot status="critical" /> Critique
                </span>
              </div>
            </div>
            <ServerPanel
              servers={filteredServers}
              total={servers.length}
              filter={filter}
              setFilter={setFilter}
              search={search}
              setSearch={setSearch}
              onSelect={setSelectedServer}
              expanded
            />
          </section>
        )}

        {view === "rules" && (
          <section className="single-view">
            <div className="view-intro">
              <div>
                <span className="section-kicker">RÉFÉRENTIEL V1.3</span>
                <h2>Des contrôles compréhensibles et vérifiables.</h2>
                <p>
                  Chaque signal explique le risque, son impact et la
                  modification concrète à appliquer.
                </p>
              </div>
              <div className="rule-count">
                <strong>{rules.length}</strong>
                <span>familles de contrôles</span>
              </div>
            </div>
            <div className="rules-grid">
              {rules.map((rule, index) => (
                <article className="rule-card" key={rule.code}>
                  <div className="rule-number">
                    {String(index + 1).padStart(2, "0")}
                  </div>
                  <span className="rule-category">{rule.category}</span>
                  <h3>{rule.title}</h3>
                  <p>{rule.detail}</p>
                  <code>{rule.code}</code>
                </article>
              ))}
            </div>
          </section>
        )}

        {view === "history" && (
          <section className="single-view">
            <div className="view-intro">
              <div>
                <span className="section-kicker">TRACES D’AUDIT</span>
                <h2>Suivez la réduction du risque.</h2>
                <p>
                  Cette première version conserve la session courante. Le
                  branchement à un historique persistant pourra être ajouté
                  ensuite.
                </p>
              </div>
            </div>
            <div className="history-layout">
              <article className="trend-card">
                <div className="trend-head">
                  <div>
                    <span>Score de posture</span>
                    <strong>+18 pts</strong>
                  </div>
                  <small>30 derniers jours</small>
                </div>
                <div className="trend-visual" aria-label="Tendance du score de 54 à 72">
                  {[54, 57, 61, 60, 66, 69, metrics.score].map(
                    (value, index) => (
                      <span
                        key={`${value}-${index}`}
                        style={{ height: `${value}%` }}
                      >
                        {index === 6 && <b>{value}</b>}
                      </span>
                    ),
                  )}
                </div>
                <div className="trend-axis">
                  <span>30 juin</span>
                  <span>Aujourd’hui</span>
                </div>
              </article>
              <div className="timeline-card">
                {[
                  {
                    date: "Aujourd’hui",
                    title: "Audit complet du parc",
                    text: `${servers.length} serveurs · ${actionableFindings.length} corrections ouvertes`,
                    tone: "green",
                  },
                  {
                    date: "22 juillet",
                    title: "2 secrets retirés",
                    text: "GitHub MCP · Sentry Reader",
                    tone: "cobalt",
                  },
                  {
                    date: "14 juillet",
                    title: "Référentiel mis à jour",
                    text: "Ajout des contrôles supply chain",
                    tone: "amber",
                  },
                  {
                    date: "30 juin",
                    title: "Premier inventaire",
                    text: "12 serveurs découverts · score 54/100",
                    tone: "gray",
                  },
                ].map((entry) => (
                  <article className="timeline-entry" key={entry.date}>
                    <span className={`timeline-dot ${entry.tone}`} />
                    <time>{entry.date}</time>
                    <div>
                      <strong>{entry.title}</strong>
                      <p>{entry.text}</p>
                    </div>
                  </article>
                ))}
              </div>
            </div>
            <article className="exception-register">
              <div className="exception-register-head">
                <div>
                  <span className="section-kicker">REGISTRE LOCAL</span>
                  <h3>Exceptions de risque</h3>
                  <p>
                    Chaque acceptation est motivée, attribuée et limitée dans
                    le temps. Le score brut continue de refléter le risque.
                  </p>
                </div>
                <span className="count-badge">{activeExceptionCount}</span>
              </div>
              {exceptionRegister.length ? (
                <div className="exception-register-list">
                  {exceptionRegister.map(({ exception, status }) => (
                    <div className="exception-register-row" key={exception.id}>
                      <span className={`exception-status ${status}`}>
                        {status === "active"
                          ? "Active"
                          : status === "expired"
                            ? "Expirée"
                            : "Révoquée"}
                      </span>
                      <div>
                        <strong>
                          {exception.serverName} · {exception.findingTitle}
                        </strong>
                        <p>{exception.reason}</p>
                        <small>
                          {exception.owner} · créée le{" "}
                          {formatExceptionDate(exception.createdAt)} · expire le{" "}
                          {formatExceptionDate(exception.expiresAt)}
                        </small>
                      </div>
                      {status === "active" ? (
                        <button
                          className="button secondary compact"
                          onClick={() => revokeException(exception.id)}
                        >
                          Révoquer
                        </button>
                      ) : null}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="exception-register-empty">
                  <span aria-hidden="true">◎</span>
                  <strong>Aucune exception enregistrée</strong>
                  <p>
                    Ouvrez un écart depuis un serveur pour documenter une
                    acceptation temporaire.
                  </p>
                </div>
              )}
            </article>
          </section>
        )}
      </main>

      {importOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setImportOpen(false);
          }}
        >
          <section
            className="import-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="import-title"
          >
            <button
              className="close-button"
              aria-label="Fermer"
              onClick={() => setImportOpen(false)}
            >
              ×
            </button>
            <span className="section-kicker">NOUVEL AUDIT</span>
            <h2 id="import-title">Importer une configuration MCP</h2>
            <p className="modal-intro">
              Formats compatibles : Claude Desktop, Cursor, VS Code ou objet
              JSON contenant <code>mcpServers</code>. L’analyse reste dans ce
              navigateur.
            </p>

            <label className="file-drop">
              <input type="file" accept=".json,application/json" onChange={handleFile} />
              <span aria-hidden="true">＋</span>
              <strong>Choisir un fichier JSON</strong>
              <small>1 Mo maximum · aucune donnée envoyée</small>
            </label>

            <div className="divider">
              <span>ou coller la configuration</span>
            </div>

            <label className="textarea-label" htmlFor="mcp-config">
              Configuration JSON
            </label>
            <textarea
              id="mcp-config"
              value={configText}
              onChange={(event) => setConfigText(event.target.value)}
              spellCheck={false}
              aria-describedby={importError ? "import-error" : undefined}
            />
            {importError && (
              <p className="form-error" id="import-error">
                {importError}
              </p>
            )}
            <div className="modal-actions">
              <button
                className="button ghost"
                onClick={() => {
                  setServers(demoServers);
                  setImportOpen(false);
                  setToast("Données de démonstration restaurées");
                  window.setTimeout(() => setToast(""), 2500);
                }}
              >
                Restaurer la démo
              </button>
              <button className="button primary" onClick={importConfiguration}>
                Analyser la configuration
                <span aria-hidden="true">→</span>
              </button>
            </div>
          </section>
        </div>
      )}

      {discoveryOpen && (
        <div
          className="modal-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) setDiscoveryOpen(false);
          }}
        >
          <section
            className="import-modal discovery-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="discovery-title"
          >
            <button
              className="close-button"
              aria-label="Fermer"
              onClick={() => setDiscoveryOpen(false)}
            >
              ×
            </button>
            <span className="section-kicker">INVENTAIRE LOCAL</span>
            <h2 id="discovery-title">Découvrir les serveurs MCP</h2>
            <p className="modal-intro">
              Le navigateur ne peut pas lire vos configurations système. Lancez
              le collecteur depuis ce dépôt, puis importez l’inventaire produit.
              Les secrets sont masqués avant l’écriture du fichier.
            </p>

            <div className="collector-command">
              <div>
                <span>WINDOWS · macOS · LINUX</span>
                <code>npm run collect:security</code>
              </div>
              <button onClick={copyCollectorCommand}>Copier</button>
            </div>

            <ul className="collector-guarantees">
              <li>Aucun serveur stdio et aucun outil MCP n’est exécuté.</li>
              <li>
                Les lockfiles npm, pnpm, Yarn, uv et Poetry sont lus sans
                lancer leur gestionnaire de paquets, y compris dans les
                monorepos.
              </li>
              <li>
                OSV reçoit uniquement les PURL avec une version exacte, jamais
                les configurations, chemins ou secrets.
              </li>
              <li>
                Seuls les endpoints HTTPS reçoivent une négociation{" "}
                <code>initialize</code>.
              </li>
              <li>
                Les preuves npm rapprochent signature, intégrité du lockfile et
                attestation SLSA vérifiée par Sigstore.
              </li>
              <li>
                Les images OCI verrouillées peuvent être vérifiées par Cosign
                ou par les attestations GitHub, avec une politique par préfixe
                et sans lancer le conteneur.
              </li>
              <li>
                Ces politiques peuvent générer un bundle d’admission Kubernetes
                sans contacter ni modifier le cluster.
              </li>
            </ul>

            <label className="file-drop">
              <input
                type="file"
                accept=".json,application/json"
                onChange={handleInventoryFile}
              />
              <span aria-hidden="true">↑</span>
              <strong>Importer mcp-inventory.json</strong>
              <small>5 Mo maximum · analyse immédiate dans ce navigateur</small>
            </label>
            {importError && (
              <p className="form-error" id="discovery-error">
                {importError}
              </p>
            )}

            <p className="collector-help">
              Sans probe ni analyse OSV : <code>npm run collect</code>. Ajoutez{" "}
              <code>--path chemin/vers/mcp.json</code> pour un fichier
              personnalisé, ou <code>--oci-policy-file</code> pour plusieurs
              identités OCI. Utilisez <code>npm run generate:admission</code>{" "}
              pour préparer leur application dans Kubernetes.
            </p>
          </section>
        </div>
      )}

      {selectedServer && (
        <div
          className="drawer-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSelectedServer(null);
              setSelectedFinding(null);
              setExceptionDraft(null);
              setExceptionError("");
            }
          }}
        >
          <aside
            className="server-drawer"
            role="dialog"
            aria-modal="true"
            aria-labelledby="server-drawer-title"
          >
            <button
              className="close-button"
              aria-label="Fermer"
              onClick={() => {
                setSelectedServer(null);
                setSelectedFinding(null);
                setExceptionDraft(null);
                setExceptionError("");
              }}
            >
              ×
            </button>
            <div className="drawer-heading">
              <div className={`server-icon ${selectedServer.status}`}>
                {selectedServer.name.slice(0, 2).toUpperCase()}
              </div>
              <div>
                <span className={`status-pill ${selectedServer.status}`}>
                  <StatusDot status={selectedServer.status} />
                  {statusLabel[selectedServer.status]}
                </span>
                <h2 id="server-drawer-title">{selectedServer.name}</h2>
                <p>
                  {selectedServer.owner} · {selectedServer.transport}
                </p>
              </div>
            </div>

            <div className="drawer-score">
              <div>
                <span>Score de sécurité</span>
                <strong>{selectedServer.score}/100</strong>
              </div>
              <div className="mini-progress">
                <span style={{ width: `${selectedServer.score}%` }} />
              </div>
            </div>

            {selectedServer.components?.length ? (
              <section
                className="supply-chain-card"
                aria-label="Composants logiciels"
              >
                <div className="supply-chain-heading">
                  <div>
                    <span className="section-kicker">SUPPLY CHAIN</span>
                    <strong>
                      {selectedServer.componentGraph
                        ? `${selectedServer.componentGraph.direct} direct${selectedServer.componentGraph.direct > 1 ? "s" : ""} · ${selectedServer.componentGraph.transitive} transitif${selectedServer.componentGraph.transitive > 1 ? "s" : ""}`
                        : `${selectedServer.components.length} composant${selectedServer.components.length > 1 ? "s" : ""}`}
                    </strong>
                  </div>
                  <div className="supply-chain-statuses">
                    {selectedServer.vulnerabilityScan ? (
                      <span
                        className={`osv-status ${selectedServer.vulnerabilityScan.status}`}
                        title={selectedServer.vulnerabilityScan.message}
                      >
                        OSV{" "}
                        {selectedServer.vulnerabilityScan.status === "complete"
                          ? "vérifié"
                          : selectedServer.vulnerabilityScan.status === "partial"
                            ? "partiel"
                            : "indisponible"}
                      </span>
                    ) : null}
                    {selectedServer.provenanceScan ? (
                      <span
                        className={`provenance-status ${selectedServer.provenanceScan.status}`}
                        title={selectedServer.provenanceScan.message}
                      >
                        SLSA{" "}
                        {selectedServer.provenanceScan.status === "complete"
                          ? "vérifié"
                          : selectedServer.provenanceScan.status === "partial"
                            ? "partiel"
                            : "indisponible"}
                      </span>
                    ) : null}
                    {selectedServer.ociVerification ? (
                      <span
                        className={`provenance-status ${selectedServer.ociVerification.status}`}
                        title={selectedServer.ociVerification.message}
                      >
                        OCI{" "}
                        {selectedServer.ociVerification.status === "complete"
                          ? "vérifié"
                          : selectedServer.ociVerification.status === "partial"
                            ? "partiel"
                            : "indisponible"}
                        {selectedServer.ociVerification.policies > 1
                          ? ` · ${selectedServer.ociVerification.policies} règles`
                          : ""}
                      </span>
                    ) : null}
                    {!selectedServer.vulnerabilityScan &&
                    !selectedServer.provenanceScan &&
                    !selectedServer.ociVerification ? (
                      <span className="supply-chain-placeholder" aria-hidden="true">
                        ⬡
                      </span>
                    ) : null}
                  </div>
                </div>
                <div className="component-list">
                  {selectedServer.components.slice(0, 200).map((component) => (
                    <article
                      className={`component-row ${component.scope ?? "direct"}`}
                      key={`${component.id}-${component.reference}`}
                    >
                      <div>
                        <span className="component-labels">
                          <span className="component-ecosystem">
                            {component.ecosystem}
                          </span>
                          <span
                            className={`component-scope ${component.scope ?? "direct"}`}
                          >
                            {component.scope === "transitive"
                              ? "transitif"
                              : "direct"}
                          </span>
                          {component.workspace ? (
                            <span className="component-workspace">
                              workspace · {component.workspace}
                            </span>
                          ) : null}
                        </span>
                        <strong>{component.name}</strong>
                        <small>
                          {component.version ?? "Version non déclarée"}
                          {component.lockfile
                            ? ` · ${component.lockfile}`
                            : ""}
                        </small>
                      </div>
                      <div className="component-row-actions">
                        {component.provenance ? (
                          <span
                            className={`component-provenance ${
                              component.provenance.registrySignature ===
                                "failed" ||
                              component.provenance.slsaProvenance === "failed"
                                ? "failed"
                                : component.provenance.registrySignature ===
                                      "verified" &&
                                    component.provenance.slsaProvenance ===
                                      "verified"
                                  ? "verified"
                                  : component.provenance.provider ===
                                        "oci-github-attestation" &&
                                      component.provenance.slsaProvenance ===
                                        "verified"
                                    ? "verified"
                                  : component.provenance.registrySignature ===
                                        "error" ||
                                      component.provenance.slsaProvenance ===
                                        "error"
                                    ? "error"
                                    : "partial"
                            }`}
                            title={`${component.provenance.message}${
                              component.provenance.policyId
                                ? ` Politique : ${component.provenance.policyId}.`
                                : ""
                            }`}
                          >
                            {component.provenance.provider === "oci-policy"
                              ? "POLITIQUE ABSENTE"
                              : component.provenance.registrySignature ===
                              "failed" ||
                            component.provenance.slsaProvenance === "failed"
                              ? "preuve invalide"
                              : component.provenance.registrySignature ===
                                    "verified" &&
                                  component.provenance.slsaProvenance ===
                                    "verified"
                                ? component.provenance.provider ===
                                  "oci-cosign"
                                  ? "COSIGN + SLSA"
                                  : "SIG + SLSA"
                                : component.provenance.provider ===
                                      "oci-github-attestation" &&
                                    component.provenance.slsaProvenance ===
                                      "verified"
                                  ? "GITHUB SLSA"
                                : component.provenance.registrySignature ===
                                    "verified"
                                  ? "SIG OK"
                                  : "preuve partielle"}
                          </span>
                        ) : null}
                        {component.vulnerabilities?.length ? (
                          <span className="vulnerability-count">
                            {component.vulnerabilities.length} avis
                          </span>
                        ) : null}
                        <span
                          className={`pin-status ${component.pinStatus}`}
                        >
                          {pinStatusLabel[component.pinStatus]}
                        </span>
                      </div>
                    </article>
                  ))}
                  {selectedServer.components.length > 200 ? (
                    <p className="component-list-limit">
                      200 composants affichés sur{" "}
                      {selectedServer.components.length}. Le rapport exporté
                      contient le graphe complet collecté.
                    </p>
                  ) : null}
                </div>
              </section>
            ) : null}

            {selectedServer.probe && (
              <section
                className={`probe-card ${selectedServer.probe.status}`}
                aria-label="Vérification MCP passive"
              >
                <div className="probe-card-heading">
                  <div>
                    <span className="section-kicker">PROBE PASSIF</span>
                    <strong>
                      {probeStatusLabel[selectedServer.probe.status]}
                    </strong>
                  </div>
                  <span className="probe-duration">
                    {selectedServer.probe.durationMs} ms
                  </span>
                </div>
                <p>{selectedServer.probe.message}</p>
                {(selectedServer.probe.protocolVersion ||
                  selectedServer.probe.capabilities?.length) && (
                  <dl>
                    {selectedServer.probe.protocolVersion && (
                      <>
                        <dt>Version</dt>
                        <dd>{selectedServer.probe.protocolVersion}</dd>
                      </>
                    )}
                    {selectedServer.probe.capabilities?.length ? (
                      <>
                        <dt>Capacités</dt>
                        <dd>
                          {selectedServer.probe.capabilities.join(", ")}
                        </dd>
                      </>
                    ) : null}
                  </dl>
                )}
              </section>
            )}

            <div className="drawer-section-head">
              <div>
                <span className="section-kicker">RÉSULTATS</span>
                <h3>
                  {selectedServer.findings.length
                    ? `${selectedServer.findings.length} correction${selectedServer.findings.length > 1 ? "s" : ""} recommandée${selectedServer.findings.length > 1 ? "s" : ""}`
                    : "Tous les contrôles sont conformes"}
                </h3>
              </div>
            </div>

            {selectedServer.findings.length ? (
              <div className="drawer-findings">
                {selectedServer.findings.map((finding) => {
                  const expanded = selectedFinding?.id === finding.id;
                  const activeException = findActiveRiskException(
                    selectedServer,
                    finding,
                    riskExceptions,
                  );
                  const latestException =
                    activeException ??
                    findLatestRiskException(
                      selectedServer,
                      finding,
                      riskExceptions,
                    );
                  const latestExceptionStatus = latestException
                    ? riskExceptionStatus(latestException)
                    : undefined;
                  const currentFindingKey = findingExceptionKey(
                    selectedServer,
                    finding,
                  );
                  const exceptionFormOpen =
                    exceptionDraft?.findingKey === currentFindingKey;
                  return (
                    <article
                      className={`drawer-finding ${expanded ? "expanded" : ""} ${activeException ? "excepted" : ""}`}
                      key={finding.id}
                    >
                      <button
                        onClick={() =>
                          setSelectedFinding(expanded ? null : finding)
                        }
                        aria-expanded={expanded}
                      >
                        <span className={`severity-icon ${finding.severity}`}>
                          !
                        </span>
                        <span>
                          <small>
                            {severityLabel[finding.severity]} · {finding.rule}
                            {activeException ? (
                              <span className="finding-exception-badge">
                                Exception active
                              </span>
                            ) : null}
                          </small>
                          <strong>{finding.title}</strong>
                        </span>
                        <span aria-hidden="true">{expanded ? "−" : "+"}</span>
                      </button>
                      {expanded && (
                        <div className="finding-detail">
                          <p>{finding.description}</p>
                          <div className="remediation-callout">
                            <span>COMMENT CORRIGER</span>
                            <p>{finding.remediation}</p>
                          </div>
                          <div className="code-block">
                            <pre>{finding.snippet}</pre>
                            <button onClick={() => copySnippet(finding)}>
                              Copier
                            </button>
                          </div>
                          {latestException ? (
                            <section
                              className={`finding-exception ${latestExceptionStatus}`}
                              aria-label="Exception de risque"
                            >
                              <div className="finding-exception-head">
                                <span>
                                  {latestExceptionStatus === "active"
                                    ? "RISQUE ACCEPTÉ TEMPORAIREMENT"
                                    : latestExceptionStatus === "expired"
                                      ? "EXCEPTION EXPIRÉE"
                                      : "EXCEPTION RÉVOQUÉE"}
                                </span>
                                <strong>
                                  {latestExceptionStatus === "active"
                                    ? `jusqu’au ${formatExceptionDate(latestException.expiresAt)}`
                                    : formatExceptionDate(
                                        latestException.revokedAt ??
                                          latestException.expiresAt,
                                      )}
                                </strong>
                              </div>
                              <p>{latestException.reason}</p>
                              <small>
                                Responsable : {latestException.owner} · créée le{" "}
                                {formatExceptionDate(latestException.createdAt)}
                              </small>
                              {latestExceptionStatus === "active" ? (
                                <button
                                  className="exception-revoke"
                                  onClick={() =>
                                    revokeException(latestException.id)
                                  }
                                >
                                  Révoquer l’exception
                                </button>
                              ) : null}
                            </section>
                          ) : null}
                          {!activeException && !exceptionFormOpen ? (
                            <button
                              className="exception-trigger"
                              onClick={() =>
                                openExceptionForm(selectedServer, finding)
                              }
                            >
                              Documenter une exception temporaire
                            </button>
                          ) : null}
                          {exceptionFormOpen ? (
                            <section
                              className="exception-form"
                              aria-label="Nouvelle exception de risque"
                            >
                              <div>
                                <span className="section-kicker">
                                  ACCEPTATION DU RISQUE
                                </span>
                                <strong>
                                  Justifiez et limitez cette exception
                                </strong>
                              </div>
                              <label>
                                Motif et référence de suivi
                                <textarea
                                  rows={3}
                                  maxLength={500}
                                  value={exceptionDraft.reason}
                                  onChange={(event) =>
                                    setExceptionDraft({
                                      ...exceptionDraft,
                                      reason: event.target.value,
                                    })
                                  }
                                  placeholder="Ex. Migration TLS suivie dans SEC-42, avec mesure compensatoire…"
                                />
                              </label>
                              <div className="exception-form-grid">
                                <label>
                                  Responsable
                                  <input
                                    maxLength={80}
                                    value={exceptionDraft.owner}
                                    onChange={(event) =>
                                      setExceptionDraft({
                                        ...exceptionDraft,
                                        owner: event.target.value,
                                      })
                                    }
                                    placeholder="Équipe ou personne"
                                  />
                                </label>
                                <label>
                                  Expiration
                                  <input
                                    type="date"
                                    min={exceptionDraft.minimumExpiresOn}
                                    max={exceptionDraft.maximumExpiresOn}
                                    value={exceptionDraft.expiresOn}
                                    onChange={(event) =>
                                      setExceptionDraft({
                                        ...exceptionDraft,
                                        expiresOn: event.target.value,
                                      })
                                    }
                                  />
                                </label>
                              </div>
                              {exceptionError ? (
                                <p className="form-error" role="alert">
                                  {exceptionError}
                                </p>
                              ) : null}
                              <div className="exception-form-actions">
                                <button
                                  className="button secondary compact"
                                  onClick={() => {
                                    setExceptionDraft(null);
                                    setExceptionError("");
                                  }}
                                >
                                  Annuler
                                </button>
                                <button
                                  className="button primary compact"
                                  onClick={() =>
                                    saveRiskException(
                                      selectedServer,
                                      finding,
                                    )
                                  }
                                >
                                  Enregistrer l’exception
                                </button>
                              </div>
                              <small>
                                Stockage local à cet appareil. L’export JSON et
                                SARIF conserve la justification et l’échéance.
                              </small>
                            </section>
                          ) : null}
                        </div>
                      )}
                    </article>
                  );
                })}
              </div>
            ) : (
              <div className="empty-success">
                <span aria-hidden="true">✓</span>
                <strong>Configuration saine</strong>
                <p>
                  Aucun écart n’a été détecté par l’analyse statique actuelle.
                  Continuez à surveiller les versions et les droits réels.
                </p>
              </div>
            )}
          </aside>
        </div>
      )}

      {toast && (
        <div className="toast" role="status">
          <span aria-hidden="true">✓</span>
          {toast}
        </div>
      )}
    </div>
  );
}

function ServerPanel({
  servers,
  total,
  filter,
  setFilter,
  search,
  setSearch,
  onSelect,
  onSeeAll,
  expanded = false,
}: {
  servers: McpServer[];
  total: number;
  filter: "all" | ServerStatus;
  setFilter: (value: "all" | ServerStatus) => void;
  search: string;
  setSearch: (value: string) => void;
  onSelect: (server: McpServer) => void;
  onSeeAll?: () => void;
  expanded?: boolean;
}) {
  return (
    <article className={`panel servers-panel ${expanded ? "expanded-panel" : ""}`}>
      <div className="panel-heading">
        <div>
          <span className="section-kicker">PARC MCP</span>
          <h2>État des serveurs</h2>
        </div>
        {onSeeAll && (
          <button className="text-button" onClick={onSeeAll}>
            Voir les {total} serveurs <span aria-hidden="true">→</span>
          </button>
        )}
      </div>
      <div className="panel-tools">
        <div className="filter-tabs" aria-label="Filtrer les serveurs">
          {(
            [
              ["all", "Tous"],
              ["critical", "Critiques"],
              ["attention", "À corriger"],
              ["secure", "Conformes"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              className={filter === value ? "active" : ""}
              onClick={() => setFilter(value)}
            >
              {label}
            </button>
          ))}
        </div>
        <label className="search-field">
          <span aria-hidden="true">⌕</span>
          <span className="sr-only">Rechercher un serveur</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Rechercher"
          />
        </label>
      </div>
      <div className="server-table" role="table" aria-label="Serveurs MCP">
        <div className="table-row table-head" role="row">
          <span role="columnheader">Serveur</span>
          <span role="columnheader">Propriétaire</span>
          <span role="columnheader">Score</span>
          <span role="columnheader">Statut</span>
          <span aria-hidden="true" />
        </div>
        {servers.map((server) => (
          <button
            className="table-row"
            role="row"
            key={server.id}
            onClick={() => onSelect(server)}
          >
            <span className="server-cell" role="cell">
              <span className={`server-icon ${server.status}`}>
                {server.name.slice(0, 2).toUpperCase()}
              </span>
              <span>
                <strong>{server.name}</strong>
                <small>
                  {server.transport} · {server.source}
                </small>
              </span>
            </span>
            <span className="owner-cell" role="cell">
              {server.owner}
            </span>
            <span className="score-cell" role="cell">
              <strong>{server.score}</strong>
              <span className="score-line">
                <i style={{ width: `${server.score}%` }} />
              </span>
            </span>
            <span role="cell">
              <span className={`status-pill ${server.status}`}>
                <StatusDot status={server.status} />
                {statusLabel[server.status]}
              </span>
            </span>
            <span className="row-arrow" aria-hidden="true">
              →
            </span>
          </button>
        ))}
        {!servers.length && (
          <div className="table-empty">
            <span aria-hidden="true">⌕</span>
            <strong>Aucun serveur ne correspond</strong>
            <p>Modifiez le filtre ou la recherche.</p>
          </div>
        )}
      </div>
    </article>
  );
}

function RemediationPanel({
  items,
  total,
  onSelect,
}: {
  items: { server: McpServer; finding: Finding }[];
  total: number;
  onSelect: (server: McpServer, finding: Finding) => void;
}) {
  return (
    <article className="panel remediation-panel">
      <div className="panel-heading">
        <div>
          <span className="section-kicker">À TRAITER EN PREMIER</span>
          <h2>Remédiations prioritaires</h2>
        </div>
        <span className="count-badge">{total}</span>
      </div>
      <div className="remediation-list">
        {items.map(({ server, finding }, index) => (
          <button
            className="remediation-item"
            key={finding.id}
            onClick={() => onSelect(server, finding)}
          >
            <span className={`priority-number ${finding.severity}`}>
              {String(index + 1).padStart(2, "0")}
            </span>
            <span className="remediation-copy">
              <span>
                <small className={finding.severity}>
                  {severityLabel[finding.severity]}
                </small>
                <i>·</i>
                <small>{server.name}</small>
              </span>
              <strong>{finding.title}</strong>
              <p>{finding.remediation}</p>
            </span>
            <span className="row-arrow" aria-hidden="true">
              →
            </span>
          </button>
        ))}
        {!items.length && (
          <div className="all-good">
            <span aria-hidden="true">✓</span>
            <strong>Aucune remédiation ouverte</strong>
            <p>La configuration importée respecte les contrôles actuels.</p>
          </div>
        )}
      </div>
      {!!items.length && (
        <div className="remediation-foot">
          <span>Priorisation par impact × exploitabilité</span>
          <span>Référentiel v1.3</span>
        </div>
      )}
    </article>
  );
}
