import { jsPDF } from "jspdf";
import {
  calculateAuditMetrics,
  type McpServer,
  type Severity,
} from "./audit-engine.ts";
import {
  findActiveRiskException,
  openFindingEntries,
  riskExceptionStatus,
  type RiskException,
} from "./finding-exceptions.ts";

type Rgb = [number, number, number];

export type AuditPdfSummary = {
  servers: number;
  score: number;
  findings: number;
  openFindings: number;
  activeExceptions: number;
};

export type AuditPdfResult = {
  bytes: Uint8Array;
  fileName: string;
  pages: number;
  summary: AuditPdfSummary;
};

const PAGE_WIDTH = 210;
const MARGIN = 15;
const CONTENT_WIDTH = PAGE_WIDTH - MARGIN * 2;
const CONTENT_BOTTOM = 278;

const COLORS = {
  ink: [23, 32, 29] as Rgb,
  muted: [92, 105, 99] as Rgb,
  subtle: [126, 137, 132] as Rgb,
  line: [220, 220, 211] as Rgb,
  paper: [248, 247, 241] as Rgb,
  green: [21, 122, 85] as Rgb,
  greenSoft: [232, 244, 238] as Rgb,
  cobalt: [36, 87, 214] as Rgb,
  cobaltSoft: [233, 238, 252] as Rgb,
  coral: [217, 71, 63] as Rgb,
  coralSoft: [250, 236, 233] as Rgb,
  amber: [184, 117, 22] as Rgb,
  amberSoft: [251, 241, 221] as Rgb,
  white: [255, 255, 255] as Rgb,
};

const severityLabel: Record<Severity, string> = {
  critical: "CRITIQUE",
  high: "ÉLEVÉ",
  medium: "MODÉRÉ",
};

const severityColor: Record<Severity, Rgb> = {
  critical: COLORS.coral,
  high: COLORS.amber,
  medium: COLORS.cobalt,
};

const severitySoftColor: Record<Severity, Rgb> = {
  critical: COLORS.coralSoft,
  high: COLORS.amberSoft,
  medium: COLORS.cobaltSoft,
};

function setTextColor(document: jsPDF, color: Rgb): void {
  document.setTextColor(color[0], color[1], color[2]);
}

function setFillColor(document: jsPDF, color: Rgb): void {
  document.setFillColor(color[0], color[1], color[2]);
}

function setDrawColor(document: jsPDF, color: Rgb): void {
  document.setDrawColor(color[0], color[1], color[2]);
}

function safeText(value: unknown, maximum = 2_000): string {
  return String(value ?? "")
    .slice(0, maximum)
    .replace(/\r\n?/g, "\n")
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/[‐‑‒–—]/g, "-")
    .replace(/…/g, "...")
    .replace(/œ/g, "oe")
    .replace(/Œ/g, "OE")
    .replace(/[^\x09\x0A\x20-\x7E\xA0-\xFF]/g, "?");
}

function paragraphText(value: unknown, maximum = 2_000): string {
  return safeText(value, maximum).replace(/\s+/g, " ").trim();
}

function codeText(value: unknown, maximum = 700): string {
  return safeText(value, maximum)
    .replace(/\t/g, "  ")
    .split("\n")
    .map((line) => line.trimEnd())
    .join("\n")
    .trim();
}

function formatDate(value: Date | string): string {
  const date = value instanceof Date ? value : new Date(value);
  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: "long",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    timeZone: "UTC",
  }).format(date);
}

function formatShortDate(value: string): string {
  return new Intl.DateTimeFormat("fr-FR", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    timeZone: "UTC",
  }).format(new Date(value));
}

function statusText(server: McpServer): string {
  if (server.status === "secure") return "Conforme";
  if (server.status === "attention") return "À corriger";
  return "Critique";
}

export function createAuditPdfReport(
  servers: McpServer[],
  exceptions: RiskException[] = [],
  generatedAt = new Date(),
): AuditPdfResult {
  const document = new jsPDF({
    compress: true,
    format: "a4",
    orientation: "portrait",
    putOnlyUsedFonts: true,
    unit: "mm",
  });
  document.setProperties({
    title: "Secure MPC - Rapport d'audit de sécurité MCP",
    subject: "Posture de sécurité et remédiations des serveurs MCP",
    author: "Secure MPC",
    creator: "Secure MPC",
    keywords: "MCP, sécurité, audit, remédiations",
  });
  document.setCreationDate(generatedAt);
  document.setLanguage("fr-FR");

  const metrics = calculateAuditMetrics(servers);
  const openFindings = openFindingEntries(servers, exceptions, generatedAt);
  const allFindings = servers
    .flatMap((server) =>
      server.findings.map((finding) => ({ server, finding })),
    )
    .sort((left, right) => {
      const order: Record<Severity, number> = {
        critical: 0,
        high: 1,
        medium: 2,
      };
      return (
        order[left.finding.severity] - order[right.finding.severity] ||
        left.server.name.localeCompare(right.server.name)
      );
    });
  const activeExceptions = exceptions.filter(
    (exception) => riskExceptionStatus(exception, generatedAt) === "active",
  );
  const summary: AuditPdfSummary = {
    servers: servers.length,
    score: metrics.score,
    findings: metrics.toFix,
    openFindings: openFindings.length,
    activeExceptions: activeExceptions.length,
  };

  let cursorY = 0;

  const drawCompactHeader = () => {
    setTextColor(document, COLORS.ink);
    document.setFont("helvetica", "bold");
    document.setFontSize(9);
    document.text("SECURE MPC", MARGIN, 15);
    setTextColor(document, COLORS.subtle);
    document.setFont("helvetica", "normal");
    document.setFontSize(7);
    document.text("RAPPORT D'AUDIT DE SÉCURITÉ MCP", PAGE_WIDTH - MARGIN, 15, {
      align: "right",
    });
    setDrawColor(document, COLORS.line);
    document.setLineWidth(0.25);
    document.line(MARGIN, 19, PAGE_WIDTH - MARGIN, 19);
  };

  const addContentPage = () => {
    document.addPage();
    drawCompactHeader();
    cursorY = 27;
  };

  const ensureSpace = (height: number): boolean => {
    if (cursorY + height <= CONTENT_BOTTOM) return false;
    addContentPage();
    return true;
  };

  const splitLines = (
    value: unknown,
    width: number,
    size: number,
    maximumLines = 50,
    style: "normal" | "bold" = "normal",
  ): string[] => {
    document.setFont("helvetica", style);
    document.setFontSize(size);
    const lines = document.splitTextToSize(paragraphText(value), width) as string[];
    if (lines.length <= maximumLines) return lines;
    const clipped = lines.slice(0, maximumLines);
    clipped[clipped.length - 1] = `${clipped[clipped.length - 1]}...`;
    return clipped;
  };

  const drawSectionTitle = (kicker: string, title: string) => {
    ensureSpace(18);
    setTextColor(document, COLORS.green);
    document.setFont("helvetica", "bold");
    document.setFontSize(7);
    document.text(safeText(kicker).toUpperCase(), MARGIN, cursorY);
    cursorY += 6;
    setTextColor(document, COLORS.ink);
    document.setFontSize(17);
    document.text(safeText(title), MARGIN, cursorY);
    cursorY += 9;
  };

  const drawParagraph = (
    value: unknown,
    options: {
      color?: Rgb;
      size?: number;
      width?: number;
      gapAfter?: number;
    } = {},
  ) => {
    const color = options.color ?? COLORS.muted;
    const size = options.size ?? 8.5;
    const width = options.width ?? CONTENT_WIDTH;
    const lineHeight = size * 0.44;
    const lines = splitLines(value, width, size);
    lines.forEach((line) => {
      ensureSpace(lineHeight + 1);
      setTextColor(document, color);
      document.setFont("helvetica", "normal");
      document.setFontSize(size);
      document.text(line, MARGIN, cursorY);
      cursorY += lineHeight;
    });
    cursorY += options.gapAfter ?? 3;
  };

  setFillColor(document, COLORS.ink);
  document.rect(0, 0, PAGE_WIDTH, 49, "F");
  setFillColor(document, COLORS.green);
  document.roundedRect(MARGIN, 12, 12, 12, 2.5, 2.5, "F");
  setTextColor(document, COLORS.white);
  document.setFont("helvetica", "bold");
  document.setFontSize(13);
  document.text("M", MARGIN + 6, 20.2, { align: "center" });
  document.setFontSize(9);
  document.text("SECURE MPC", MARGIN + 17, 17);
  document.setFont("helvetica", "normal");
  document.setFontSize(7);
  document.text("SECURITY WORKSPACE", MARGIN + 17, 21.5);
  document.setFont("helvetica", "bold");
  document.setFontSize(21);
  document.text("Rapport d'audit de sécurité MCP", MARGIN, 35);
  document.setFont("helvetica", "normal");
  document.setFontSize(7.5);
  document.text(
    `Généré localement le ${safeText(formatDate(generatedAt))}`,
    MARGIN,
    42,
  );

  cursorY = 61;
  setTextColor(document, COLORS.green);
  document.setFont("helvetica", "bold");
  document.setFontSize(7);
  document.text("SYNTHÈSE EXÉCUTIVE", MARGIN, cursorY);
  cursorY += 7;
  setTextColor(document, COLORS.ink);
  document.setFontSize(16);
  document.text(
    openFindings.length
      ? "Des corrections restent nécessaires."
      : "Aucune correction ouverte dans le perimetre.",
    MARGIN,
    cursorY,
  );
  cursorY += 10;

  const cards = [
    { label: "SCORE BRUT", value: `${metrics.score}/100`, color: COLORS.green },
    { label: "SERVEURS", value: String(servers.length), color: COLORS.cobalt },
    {
      label: "RISQUES DÉTECTÉS",
      value: String(metrics.toFix),
      color: COLORS.coral,
    },
    {
      label: "CORRECTIONS OUVERTES",
      value: String(openFindings.length),
      color: COLORS.amber,
    },
  ];
  const cardGap = 4;
  const cardWidth = (CONTENT_WIDTH - cardGap * 3) / 4;
  cards.forEach((card, index) => {
    const x = MARGIN + index * (cardWidth + cardGap);
    setFillColor(document, COLORS.paper);
    setDrawColor(document, COLORS.line);
    document.roundedRect(x, cursorY, cardWidth, 23, 2, 2, "FD");
    setTextColor(document, card.color);
    document.setFont("helvetica", "bold");
    document.setFontSize(15);
    document.text(card.value, x + 4, cursorY + 10);
    setTextColor(document, COLORS.subtle);
    document.setFontSize(6.2);
    document.text(card.label, x + 4, cursorY + 17);
  });
  cursorY += 31;

  const narrative = openFindings.length
    ? `${openFindings.length} correction${openFindings.length > 1 ? "s" : ""} reste${openFindings.length > 1 ? "nt" : ""} ouverte${openFindings.length > 1 ? "s" : ""}. Le score reste brut : une acceptation temporaire ne masque pas le risque détecté.`
    : "Les contrôles actuels ne relèvent aucune correction ouverte. Continuez à surveiller les versions, les identités de publication et les permissions réelles.";
  drawParagraph(narrative, { size: 9, gapAfter: 2 });
  if (activeExceptions.length) {
    setFillColor(document, COLORS.amberSoft);
    setDrawColor(document, COLORS.amber);
    const lines = splitLines(
      `${activeExceptions.length} risque${activeExceptions.length > 1 ? "s" : ""} sous exception active. Chaque exception reste datée et apparaît dans le registre de ce rapport.`,
      CONTENT_WIDTH - 10,
      8,
    );
    const height = 10 + lines.length * 3.5;
    document.roundedRect(MARGIN, cursorY, CONTENT_WIDTH, height, 2, 2, "FD");
    setTextColor(document, COLORS.amber);
    document.setFont("helvetica", "bold");
    document.setFontSize(8);
    lines.forEach((line, index) =>
      document.text(line, MARGIN + 5, cursorY + 7 + index * 3.5),
    );
    cursorY += height + 5;
  }

  drawSectionTitle("PÉRIMÈTRE", "Inventaire des serveurs");
  const column = {
    name: MARGIN,
    transport: MARGIN + 73,
    score: MARGIN + 108,
    status: MARGIN + 133,
    findings: PAGE_WIDTH - MARGIN,
  };
  const drawServerHeader = () => {
    setFillColor(document, COLORS.ink);
    document.rect(MARGIN, cursorY, CONTENT_WIDTH, 8, "F");
    setTextColor(document, COLORS.white);
    document.setFont("helvetica", "bold");
    document.setFontSize(6.5);
    document.text("SERVEUR", column.name + 3, cursorY + 5.2);
    document.text("TRANSPORT", column.transport, cursorY + 5.2);
    document.text("SCORE", column.score, cursorY + 5.2);
    document.text("STATUT", column.status, cursorY + 5.2);
    document.text("ÉCARTS", column.findings, cursorY + 5.2, {
      align: "right",
    });
    cursorY += 8;
  };
  drawServerHeader();
  servers.forEach((server, index) => {
    const nameLines = splitLines(server.name, 66, 7.5, 2, "bold");
    const rowHeight = Math.max(10, 5 + nameLines.length * 3.2);
    if (ensureSpace(rowHeight)) drawServerHeader();
    if (index % 2 === 0) {
      setFillColor(document, COLORS.paper);
      document.rect(MARGIN, cursorY, CONTENT_WIDTH, rowHeight, "F");
    }
    setTextColor(document, COLORS.ink);
    document.setFont("helvetica", "bold");
    document.setFontSize(7.5);
    nameLines.forEach((line, lineIndex) =>
      document.text(line, column.name + 3, cursorY + 5 + lineIndex * 3.2),
    );
    document.setFont("helvetica", "normal");
    document.setFontSize(7);
    setTextColor(document, COLORS.muted);
    document.text(safeText(server.transport, 30), column.transport, cursorY + 5);
    document.text(String(server.score), column.score, cursorY + 5);
    document.text(statusText(server), column.status, cursorY + 5);
    document.text(String(server.findings.length), column.findings, cursorY + 5, {
      align: "right",
    });
    setDrawColor(document, COLORS.line);
    document.line(MARGIN, cursorY + rowHeight, PAGE_WIDTH - MARGIN, cursorY + rowHeight);
    cursorY += rowHeight;
  });
  cursorY += 7;

  drawSectionTitle("PLAN D'ACTION", "Risques et remédiations");
  if (!allFindings.length) {
    setFillColor(document, COLORS.greenSoft);
    document.roundedRect(MARGIN, cursorY, CONTENT_WIDTH, 20, 2, 2, "F");
    setTextColor(document, COLORS.green);
    document.setFont("helvetica", "bold");
    document.setFontSize(9);
    document.text(
      "Aucun écart détecté par l'analyse statique actuelle.",
      MARGIN + 5,
      cursorY + 8,
    );
    setTextColor(document, COLORS.muted);
    document.setFont("helvetica", "normal");
    document.setFontSize(7.5);
    document.text(
      "Vérifiez néanmoins les droits réels et le comportement à l'exécution.",
      MARGIN + 5,
      cursorY + 14,
    );
    cursorY += 27;
  }

  allFindings.forEach(({ server, finding }, index) => {
    const activeException = findActiveRiskException(
      server,
      finding,
      exceptions,
      generatedAt,
    );
    const titleLines = splitLines(
      `${server.name} - ${finding.title}`,
      CONTENT_WIDTH - 12,
      10,
      2,
      "bold",
    );
    const descriptionLines = splitLines(
      finding.description,
      CONTENT_WIDTH - 12,
      7.5,
      7,
    );
    const remediationLines = splitLines(
      finding.remediation,
      CONTENT_WIDTH - 12,
      7.5,
      9,
      "bold",
    );
    const snippet = codeText(finding.snippet);
    document.setFont("courier", "normal");
    document.setFontSize(6.3);
    const snippetLines = snippet
      ? snippet
          .split("\n")
          .flatMap(
            (line) =>
              document.splitTextToSize(line || " ", CONTENT_WIDTH - 18) as string[],
          )
          .slice(0, 8)
      : [];
    const exceptionLines = activeException
      ? splitLines(activeException.reason, CONTENT_WIDTH - 12, 7, 5)
      : [];
    const height =
      22 +
      (titleLines.length - 1) * 4 +
      descriptionLines.length * 3.3 +
      remediationLines.length * 3.3 +
      (snippetLines.length ? 9 + snippetLines.length * 3 : 0) +
      (activeException ? 11 + exceptionLines.length * 3 : 0);
    ensureSpace(height + 5);

    setFillColor(document, severitySoftColor[finding.severity]);
    setDrawColor(document, COLORS.line);
    document.roundedRect(MARGIN, cursorY, CONTENT_WIDTH, height, 2, 2, "FD");
    setFillColor(document, severityColor[finding.severity]);
    document.roundedRect(MARGIN, cursorY, 2.2, height, 1, 1, "F");
    setTextColor(document, severityColor[finding.severity]);
    document.setFont("helvetica", "bold");
    document.setFontSize(6.5);
    document.text(
      `${String(index + 1).padStart(2, "0")}  ${severityLabel[finding.severity]}  ${safeText(finding.rule)}`,
      MARGIN + 6,
      cursorY + 6,
    );
    if (activeException) {
      document.text("SOUS EXCEPTION ACTIVE", PAGE_WIDTH - MARGIN - 5, cursorY + 6, {
        align: "right",
      });
    }
    setTextColor(document, COLORS.ink);
    document.setFontSize(10);
    titleLines.forEach((line, lineIndex) =>
      document.text(line, MARGIN + 6, cursorY + 12 + lineIndex * 4),
    );

    let detailY = cursorY + 17 + (titleLines.length - 1) * 4;
    setTextColor(document, COLORS.muted);
    document.setFont("helvetica", "normal");
    document.setFontSize(7.5);
    descriptionLines.forEach((line) => {
      document.text(line, MARGIN + 6, detailY);
      detailY += 3.3;
    });
    detailY += 2;
    setTextColor(document, COLORS.green);
    document.setFont("helvetica", "bold");
    document.setFontSize(6.5);
    document.text("CORRECTION RECOMMANDÉE", MARGIN + 6, detailY);
    detailY += 4;
    setTextColor(document, COLORS.ink);
    document.setFontSize(7.5);
    remediationLines.forEach((line) => {
      document.text(line, MARGIN + 6, detailY);
      detailY += 3.3;
    });
    if (snippetLines.length) {
      detailY += 2;
      const codeHeight = 5 + snippetLines.length * 3;
      setFillColor(document, COLORS.ink);
      document.roundedRect(
        MARGIN + 6,
        detailY,
        CONTENT_WIDTH - 12,
        codeHeight,
        1.5,
        1.5,
        "F",
      );
      setTextColor(document, COLORS.white);
      document.setFont("courier", "normal");
      document.setFontSize(6.3);
      snippetLines.forEach((line, lineIndex) =>
        document.text(
          safeText(line, 180),
          MARGIN + 9,
          detailY + 4 + lineIndex * 3,
        ),
      );
      detailY += codeHeight;
    }
    if (activeException) {
      detailY += 3;
      setTextColor(document, COLORS.amber);
      document.setFont("helvetica", "bold");
      document.setFontSize(6.5);
      document.text(
        `RISQUE ACCEPTÉ PAR ${safeText(activeException.owner, 80).toUpperCase()} JUSQU'AU ${safeText(formatShortDate(activeException.expiresAt)).toUpperCase()}`,
        MARGIN + 6,
        detailY,
      );
      detailY += 4;
      setTextColor(document, COLORS.muted);
      document.setFont("helvetica", "normal");
      document.setFontSize(7);
      exceptionLines.forEach((line) => {
        document.text(line, MARGIN + 6, detailY);
        detailY += 3;
      });
    }
    cursorY += height + 5;
  });

  if (exceptions.length) {
    drawSectionTitle("GOUVERNANCE", "Registre des exceptions");
    exceptions
      .slice()
      .sort(
        (left, right) =>
          Date.parse(right.createdAt) - Date.parse(left.createdAt),
      )
      .forEach((exception) => {
        const status = riskExceptionStatus(exception, generatedAt);
        const exceptionStatusLabel =
          status === "active"
            ? "ACTIVE"
            : status === "expired"
              ? "EXPIRÉE"
              : "RÉVOQUÉE";
        const reasonLines = splitLines(
          exception.reason,
          CONTENT_WIDTH - 10,
          7.3,
          5,
        );
        const height = 14 + reasonLines.length * 3.2;
        ensureSpace(height + 4);
        const tone =
          status === "active"
            ? COLORS.amber
            : status === "expired"
              ? COLORS.coral
              : COLORS.subtle;
        setDrawColor(document, COLORS.line);
        setFillColor(document, COLORS.paper);
        document.roundedRect(MARGIN, cursorY, CONTENT_WIDTH, height, 2, 2, "FD");
        setTextColor(document, tone);
        document.setFont("helvetica", "bold");
        document.setFontSize(6.5);
        document.text(exceptionStatusLabel, MARGIN + 5, cursorY + 5.5);
        setTextColor(document, COLORS.ink);
        document.setFontSize(8.5);
        document.text(
          safeText(`${exception.serverName} - ${exception.findingTitle}`, 260),
          MARGIN + 27,
          cursorY + 5.5,
        );
        setTextColor(document, COLORS.muted);
        document.setFont("helvetica", "normal");
        document.setFontSize(7);
        document.text(
          `${safeText(exception.owner, 80)} - création ${formatShortDate(exception.createdAt)} - expiration ${formatShortDate(exception.expiresAt)}`,
          MARGIN + 5,
          cursorY + 10.5,
        );
        reasonLines.forEach((line, lineIndex) =>
          document.text(line, MARGIN + 5, cursorY + 15 + lineIndex * 3.2),
        );
        cursorY += height + 4;
      });
  }

  drawSectionTitle("MÉTHODOLOGIE", "Portée et limites");
  drawParagraph(
    "Ce rapport est produit par une analyse statique locale des configurations et des preuves collectées. Il ne remplace pas un test d'intrusion, une revue des permissions effectivement accordées, une validation kubectl côté cluster ou une surveillance du comportement à l'exécution.",
    { size: 8.2, gapAfter: 2 },
  );
  drawParagraph(
    "Les secrets détectés sont masqués. Les exceptions restent des acceptations temporaires de risque : elles ne constituent pas une correction et ne réduisent pas le score brut.",
    { size: 8.2 },
  );

  const totalPages = document.getNumberOfPages();
  for (let page = 1; page <= totalPages; page += 1) {
    document.setPage(page);
    setDrawColor(document, COLORS.line);
    document.setLineWidth(0.25);
    document.line(MARGIN, 284, PAGE_WIDTH - MARGIN, 284);
    setTextColor(document, COLORS.subtle);
    document.setFont("helvetica", "normal");
    document.setFontSize(6.5);
    document.text(
      `Secure MPC - Analyse statique locale - ${safeText(formatDate(generatedAt))}`,
      MARGIN,
      289,
    );
    document.text(`Page ${page} / ${totalPages}`, PAGE_WIDTH - MARGIN, 289, {
      align: "right",
    });
  }

  return {
    bytes: new Uint8Array(document.output("arraybuffer")),
    fileName: `secure-mpc-audit-${generatedAt.toISOString().slice(0, 10)}.pdf`,
    pages: totalPages,
    summary,
  };
}
