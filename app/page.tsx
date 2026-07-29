"use client";

import { ChangeEvent, CSSProperties, useMemo, useState } from "react";

type Severity = "critical" | "high" | "medium";
type ServerStatus = "critical" | "attention" | "secure";
type View = "overview" | "servers" | "rules" | "history";

type Finding = {
  id: string;
  severity: Severity;
  title: string;
  description: string;
  remediation: string;
  snippet: string;
  rule: string;
};

type McpServer = {
  id: string;
  name: string;
  owner: string;
  transport: string;
  source: string;
  score: number;
  status: ServerStatus;
  controls: number;
  findings: Finding[];
  lastScan: string;
};

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

const rules = [
  {
    code: "MCP-SEC-01",
    title: "Gestion des secrets",
    detail: "Détecte les jetons et mots de passe stockés en clair dans les configurations.",
    category: "Secrets",
  },
  {
    code: "MCP-AUTHZ-01",
    title: "Moindre privilège",
    detail: "Vérifie que les rôles, portées et chemins exposés sont limités au strict nécessaire.",
    category: "Accès",
  },
  {
    code: "MCP-NET-01",
    title: "Transport chiffré",
    detail: "Refuse HTTP et signale les transports distants sans authentification explicite.",
    category: "Réseau",
  },
  {
    code: "MCP-SUP-02",
    title: "Versions verrouillées",
    detail: "Signale les paquets latest, non versionnés ou récupérés dynamiquement.",
    category: "Supply chain",
  },
  {
    code: "MCP-EXEC-01",
    title: "Exécution directe",
    detail: "Détecte les shells intermédiaires et les commandes permettant une injection.",
    category: "Exécution",
  },
  {
    code: "MCP-EXEC-02",
    title: "Isolation du processus",
    detail: "Recherche les options qui désactivent sandbox, confirmations ou contrôles d’accès.",
    category: "Exécution",
  },
  {
    code: "MCP-AUDIT-01",
    title: "Traçabilité",
    detail: "Contrôle la présence d’une identité, d’un contexte et d’une journalisation exploitable.",
    category: "Audit",
  },
  {
    code: "MCP-DATA-01",
    title: "Minimisation des données",
    detail: "Identifie les accès globaux aux fichiers, bases ou espaces de connaissance.",
    category: "Données",
  },
];

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

function isSensitiveKey(key: string) {
  return /(token|secret|password|passwd|api.?key|authorization|credential)/i.test(
    key,
  );
}

function containsConcreteSecret(value: unknown): boolean {
  if (typeof value !== "string") return false;
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("${") || trimmed.includes("<")) return false;
  return trimmed.length >= 8;
}

function inspectForSecrets(value: unknown, parentKey = ""): boolean {
  if (Array.isArray(value)) {
    return value.some((item) => inspectForSecrets(item, parentKey));
  }
  if (value && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(
      ([key, child]) =>
        (isSensitiveKey(key) && containsConcreteSecret(child)) ||
        inspectForSecrets(child, key),
    );
  }
  return isSensitiveKey(parentKey) && containsConcreteSecret(value);
}

function auditConfiguration(raw: string): McpServer[] {
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  const container =
    (parsed.mcpServers as Record<string, unknown> | undefined) ??
    (parsed.servers as Record<string, unknown> | undefined) ??
    parsed;

  if (!container || typeof container !== "object" || Array.isArray(container)) {
    throw new Error("Aucun objet de serveurs MCP n’a été trouvé.");
  }

  return Object.entries(container).map(([name, value], index) => {
    const config =
      value && typeof value === "object"
        ? (value as Record<string, unknown>)
        : {};
    const command = String(config.command ?? "");
    const url = String(config.url ?? "");
    const args = Array.isArray(config.args)
      ? config.args.map((item) => String(item))
      : [];
    const text = `${command} ${args.join(" ")} ${url}`.toLowerCase();
    const findings: Finding[] = [];

    if (inspectForSecrets(config)) {
      findings.push(
        makeFinding(
          `${name}-secret`,
          "critical",
          "Secret stocké dans la configuration",
          "Une valeur sensible semble être présente en clair. La valeur détectée n’est ni affichée ni conservée.",
          "Révoquez la valeur si elle a été partagée, puis injectez-la depuis un coffre de secrets ou une variable d’environnement.",
          `"env": {\n  "SERVICE_TOKEN": "\${SERVICE_TOKEN}"\n}`,
          "MCP-SEC-01",
        ),
      );
    }

    if (url.startsWith("http://")) {
      findings.push(
        makeFinding(
          `${name}-http`,
          "critical",
          "Transport HTTP non chiffré",
          "Le point d’accès distant ne protège pas les données et jetons en transit.",
          "Publiez ce serveur derrière HTTPS avec un certificat valide et bloquez les redirections vers HTTP.",
          `"url": "${url.replace("http://", "https://")}"`,
          "MCP-NET-01",
        ),
      );
    }

    if (/(bash|sh|cmd|powershell|pwsh)(\.exe)?$/i.test(command)) {
      findings.push(
        makeFinding(
          `${name}-shell`,
          "critical",
          "Exécution via un shell",
          "Un interpréteur de commandes augmente le risque d’injection et masque le binaire réellement exécuté.",
          "Appelez directement le binaire ou le script du serveur avec une liste d’arguments explicite.",
          `"command": "/opt/mcp/server"\n"args": ["--readonly"]`,
          "MCP-EXEC-01",
        ),
      );
    }

    if (
      /(no-sandbox|allow-all|skip-permission|disable-security|dangerously)/i.test(
        text,
      )
    ) {
      findings.push(
        makeFinding(
          `${name}-unsafe`,
          "critical",
          "Option de sécurité désactivée",
          "Une option dangereuse contourne une protection d’isolation ou d’autorisation.",
          "Supprimez ce paramètre et définissez explicitement les ressources et opérations autorisées.",
          `"args": ["--readonly", "--workspace", "/workspace/project"]`,
          "MCP-EXEC-02",
        ),
      );
    }

    const packageArg = args.find(
      (arg) => !arg.startsWith("-") && /[a-z0-9@/_-]+/i.test(arg),
    );
    if (
      command.toLowerCase().includes("npx") &&
      packageArg &&
      (!/@[^/]+$/.test(packageArg) || packageArg.endsWith("@latest"))
    ) {
      findings.push(
        makeFinding(
          `${name}-version`,
          "high",
          "Paquet non verrouillé",
          "Le gestionnaire peut télécharger et exécuter une version différente sans revue préalable.",
          "Indiquez une version exacte et effectuez les mises à jour dans une procédure contrôlée.",
          `"args": ["-y", "${packageArg.replace(/@latest$/, "")}@1.0.0"]`,
          "MCP-SUP-02",
        ),
      );
    }

    const broadPath = args.some(
      (arg) =>
        arg === "/" ||
        /^[a-z]:\\?$/i.test(arg) ||
        /^~[/\\]?$/.test(arg) ||
        /users[/\\][^/\\]+$/i.test(arg),
    );
    if (broadPath || /filesystem/.test(text) && args.includes("/")) {
      findings.push(
        makeFinding(
          `${name}-path`,
          "critical",
          "Accès fichiers trop large",
          "Le serveur peut atteindre une racine système ou un répertoire utilisateur complet.",
          "Montez uniquement un dossier de travail dédié et rendez-le accessible en lecture seule si possible.",
          `"args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/workspace/project"]`,
          "MCP-AUTHZ-03",
        ),
      );
    }

    if (url.startsWith("https://") && !config.headers && !config.auth) {
      findings.push(
        makeFinding(
          `${name}-auth`,
          "medium",
          "Authentification distante à confirmer",
          "Aucun mécanisme d’authentification n’est visible dans cette configuration statique.",
          "Vérifiez que le serveur impose OAuth 2.1 ou un jeton court, lié à l’audience et injecté hors configuration.",
          `"headers": {\n  "Authorization": "Bearer \${MCP_ACCESS_TOKEN}"\n}`,
          "MCP-AUTHN-01",
        ),
      );
    }

    const penalty = findings.reduce(
      (sum, finding) =>
        sum +
        (finding.severity === "critical"
          ? 28
          : finding.severity === "high"
            ? 17
            : 8),
      0,
    );
    const score = Math.max(12, 100 - penalty);
    const status: ServerStatus = findings.some(
      (finding) => finding.severity === "critical",
    )
      ? "critical"
      : findings.length
        ? "attention"
        : "secure";

    return {
      id: `imported-${index}-${name}`,
      name,
      owner: "Non attribué",
      transport: url ? (url.startsWith("https") ? "HTTPS" : "HTTP") : "Stdio",
      source: "Import local",
      score,
      status,
      controls: 8,
      findings,
      lastScan: "à l’instant",
    };
  });
}

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
  const [configText, setConfigText] = useState(sampleConfig);
  const [importError, setImportError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [toast, setToast] = useState("");
  const [lastAudit, setLastAudit] = useState("Aujourd’hui, 14:32");

  const metrics = useMemo(() => {
    const findings = servers.flatMap((server) => server.findings);
    return {
      score: servers.length
        ? Math.round(
            servers.reduce((sum, server) => sum + server.score, 0) /
              servers.length,
          )
        : 0,
      controls: servers.reduce((sum, server) => sum + server.controls, 0),
      critical: findings.filter(
        (finding) => finding.severity === "critical",
      ).length,
      toFix: findings.length,
      secure: servers.filter((server) => server.status === "secure").length,
    };
  }, [servers]);

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
      servers
        .flatMap((server) =>
          server.findings.map((finding) => ({ server, finding })),
        )
        .sort((a, b) => {
          const order: Record<Severity, number> = {
            critical: 0,
            high: 1,
            medium: 2,
          };
          return order[a.finding.severity] - order[b.finding.severity];
        }),
    [servers],
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

  const importConfiguration = () => {
    setImportError("");
    try {
      const audited = auditConfiguration(configText);
      if (!audited.length) {
        throw new Error("La configuration ne contient aucun serveur.");
      }
      setServers(audited);
      setImportOpen(false);
      setFilter("all");
      setSearch("");
      setLastAudit("à l’instant");
      setToast(
        `${audited.length} serveur${audited.length > 1 ? "s" : ""} importé${audited.length > 1 ? "s" : ""} et analysé${audited.length > 1 ? "s" : ""} localement`,
      );
      window.setTimeout(() => setToast(""), 3500);
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

  const copySnippet = async (finding: Finding) => {
    await navigator.clipboard.writeText(finding.snippet);
    setToast("Correctif copié dans le presse-papiers");
    window.setTimeout(() => setToast(""), 2200);
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
            <button
              className="button secondary"
              onClick={() => setImportOpen(true)}
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
                    {metrics.critical
                      ? `${metrics.critical} risques critiques nécessitent une action immédiate.`
                      : "Aucun risque critique détecté sur la configuration actuelle."}
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
                    <strong>{metrics.critical}</strong>
                  </div>
                  <small>Action immédiate</small>
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
                total={metrics.toFix}
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
                    text: `${servers.length} serveurs · ${metrics.toFix} corrections ouvertes`,
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

      {selectedServer && (
        <div
          className="drawer-backdrop"
          role="presentation"
          onMouseDown={(event) => {
            if (event.target === event.currentTarget) {
              setSelectedServer(null);
              setSelectedFinding(null);
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
                  return (
                    <article
                      className={`drawer-finding ${expanded ? "expanded" : ""}`}
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
