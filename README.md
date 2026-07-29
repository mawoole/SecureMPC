# MCP Sentinel

[![CI](https://github.com/mawoole/SecureMPC/actions/workflows/ci.yml/badge.svg)](https://github.com/mawoole/SecureMPC/actions/workflows/ci.yml)

![Aperçu MCP Sentinel](public/og.png)

MCP Sentinel est une application web d’audit de configurations MCP
([Model Context Protocol](https://modelcontextprotocol.io/)). Elle transforme un
inventaire de serveurs difficile à relire en une posture de sécurité claire :
score global, risques prioritaires, explication de l’impact et correctifs
directement applicables.

> Le moteur actuel réalise une **analyse statique locale** des configurations.
> Il ne remplace pas un test d’intrusion, une revue des permissions réellement
> accordées ni une surveillance d’exécution.

## Fonctionnalités

- import d’un fichier JSON ou collage direct d’une configuration ;
- collecteur local multiplateforme pour inventorier les configurations connues ;
- découverte de Claude Desktop, Cursor, VS Code, Windsurf et des workspaces ;
- masquage des secrets avant la création de l’inventaire ;
- vérification MCP passive et optionnelle des endpoints HTTPS ;
- affichage de la version négociée et des capacités annoncées ;
- inventaire des composants npm, PyPI, OCI et exécutables locaux ;
- détection des tags d’images mutables et dépendances non verrouillées ;
- prise en charge des objets `mcpServers` utilisés par Claude Desktop, Cursor
  et VS Code ;
- détection locale des secrets présents en clair ;
- contrôle du chiffrement des transports distants ;
- détection des shells intermédiaires et options dangereuses ;
- signalement des dépendances non verrouillées ;
- contrôle des chemins de fichiers trop larges ;
- vérification du principe de moindre privilège ;
- score de sécurité global et par serveur ;
- priorisation par criticité ;
- remédiations expliquées avec extraits de configuration copiables ;
- export de rapports JSON, SARIF et d’un SBOM CycloneDX 1.7 ;
- vues dédiées aux serveurs, règles et audits ;
- interface responsive et accessible au clavier.

## Confidentialité

L’analyse statique est effectuée dans le navigateur. La découverte est effectuée
par un collecteur local explicite :

- aucune configuration importée n’est envoyée à un service distant ;
- les valeurs sensibles détectées ne sont jamais affichées ;
- aucun secret n’est enregistré dans le stockage du navigateur ;
- les secrets concrets sont remplacés par `${REDACTED}` avant l’écriture de
  l’inventaire ;
- le collecteur ne lance jamais les commandes des serveurs `stdio` ;
- le probe n’envoie jamais les en-têtes d’authentification trouvés dans les
  configurations ;
- le probe ne contacte que les endpoints HTTPS et n’appelle aucun outil MCP ;
- les données de démonstration peuvent être restaurées à tout moment.

Même avec ces protections, évitez de partager ou de committer une configuration
contenant de vrais secrets. Si une valeur sensible a déjà été exposée, révoquez
et renouvelez-la.

## Démarrage rapide

### Prérequis

- Node.js `22.13` ou supérieur ;
- npm ;
- Git.

### Installation

```bash
git clone https://github.com/mawoole/SecureMPC.git
cd SecureMPC
npm ci
npm run dev
```

Ouvrez ensuite [http://localhost:3000](http://localhost:3000).

### Vérification de production

```bash
npm run build
```

## Utilisation

1. Ouvrez **Importer**.
2. Choisissez un fichier JSON ou collez une configuration.
3. Cliquez sur **Analyser la configuration**.
4. Consultez le score et les remédiations prioritaires.
5. Ouvrez un serveur pour voir l’impact et copier le correctif recommandé.

Exemple minimal :

```json
{
  "mcpServers": {
    "filesystem-project": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-filesystem@1.0.0",
        "/workspace/project"
      ]
    },
    "internal-api": {
      "url": "https://mcp.internal.example/v1",
      "headers": {
        "Authorization": "Bearer ${MCP_ACCESS_TOKEN}"
      }
    }
  }
}
```

## Découverte locale

Depuis le dossier du projet, créez un inventaire assaini :

```bash
npm run collect
```

Le fichier `mcp-inventory.json` est produit dans le dossier courant. Ouvrez
ensuite **Découvrir** dans l’application et importez ce fichier. L’inventaire
local est ignoré par Git afin d’éviter de publier des métadonnées
d’infrastructure.

Pour vérifier également les endpoints MCP distants :

```bash
npm run collect -- --probe
```

Le probe réalise uniquement la négociation MCP `initialize`, envoie la
notification `initialized`, relève la version et les capacités annoncées, puis
ferme la session lorsque le serveur en a créé une. Il n’appelle ni `tools/list`
ni `tools/call`. Un endpoint qui répond `401` ou `403` est classé comme
joignable avec authentification exigée, sans tentative de connexion.

Options utiles :

```bash
# Ajouter un fichier non standard
npm run collect -- --path ./config/mcp.json

# Limiter la recherche workspace à un autre projet
npm run collect -- --workspace ../autre-projet

# Adapter le délai réseau, au maximum 15 secondes
npm run collect -- --probe --timeout 10000

# Choisir le fichier de sortie
npm run collect -- --output ./mcp-inventory-equipe.json

# Produire également un SBOM CycloneDX
npm run collect -- --sbom
```

### Inventaire supply chain et SBOM

MCP Sentinel reconnaît les lanceurs suivants sans les exécuter :

- npm : `npx`, `npm exec`, `pnpm dlx`, `yarn dlx` et `bunx` ;
- Python : `uvx` et `pipx run` ;
- conteneurs : `docker run`, `podman run` et `nerdctl run` ;
- exécutables locaux, enregistrés sans chemin personnel ni version inventée.

Une version npm exacte ou une contrainte PyPI `==` est considérée comme
verrouillée. Pour une image OCI, seul un digest SHA-256 complet est immuable :
un tag comme `1.4.0` reste modifiable dans le registre.

La commande suivante produit `mcp-inventory.json` et
`mcp-sbom.cdx.json` :

```bash
npm run collect:sbom
```

Le même SBOM peut être téléchargé depuis le menu **Exporter** de l’application.
Il utilise CycloneDX 1.7, des identifiants
[Package URL](https://github.com/package-url/purl-spec) et un graphe reliant
chaque serveur MCP à ses composants détectés.

### Emplacements reconnus

| Client | Windows | macOS | Linux |
| --- | --- | --- | --- |
| Claude Desktop | `%APPDATA%\Claude\claude_desktop_config.json` | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` |
| Cursor | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` |
| VS Code | `%APPDATA%\Code\User\mcp.json` | `~/Library/Application Support/Code/User/mcp.json` | `~/.config/Code/User/mcp.json` |
| Windsurf | `~/.codeium/windsurf/mcp_config.json` | idem | idem |
| Workspace | `.vscode/mcp.json`, `.cursor/mcp.json` | idem | idem |

Les fichiers `settings.json` de VS Code sont aussi inspectés lorsque présents.
Les chemins personnels sont normalisés avec `~` dans l’inventaire. Sous macOS
et Linux, le fichier produit reçoit des permissions `0600`.

Le probe suit la version stable `2025-11-25` de la
[spécification MCP](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle)
et accepte les réponses JSON comme Server-Sent Events définies par le
[transport Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

## Contrôles de sécurité

| Famille | Ce qui est vérifié | Exemple de correction |
| --- | --- | --- |
| Secrets | Jetons, mots de passe et clés présents en clair | Injection par variable d’environnement ou coffre de secrets |
| Transport | URL HTTP et absence d’authentification visible | HTTPS et jeton court lié à l’audience |
| Exécution | Shells intermédiaires et options désactivant la sécurité | Appel direct du binaire et sandbox active |
| Supply chain | Paquets npm/PyPI non verrouillés et images OCI sans digest | Version exacte ou digest SHA-256 revu |
| Autorisations | Racines de disque, comptes administrateurs et portées larges | Chemin dédié, rôle en lecture seule et scopes minimaux |
| Audit | Identité et corrélation insuffisantes | Identifiant de session et journalisation de métadonnées |

Les contrôles sont volontairement conservateurs. Un signal signifie qu’une
revue est nécessaire ; il ne prouve pas à lui seul qu’une vulnérabilité est
exploitable.

## Architecture

- **Next.js 16 / React 19** pour l’interface ;
- **TypeScript** pour le moteur d’analyse et les composants ;
- **vinext / Vite** pour la construction ;
- aucune base de données pour la première version ;
- aucune API distante requise pour auditer une configuration.

Principaux fichiers :

```text
app/
  page.tsx       Interface et orchestration des audits
  globals.css    Système visuel responsive
  layout.tsx     Métadonnées et partage social
lib/
  audit-engine.ts  Règles, scoring et exports JSON/SARIF
  collector.ts     Découverte, redaction et probe MCP passif
  supply-chain.ts  Détection des composants et export CycloneDX
tools/
  collector.ts     Interface en ligne de commande multiplateforme
tests/
  audit-engine.test.ts     Tests de sécurité du moteur
  collector.test.ts        Tests du collecteur et du protocole passif
  supply-chain.test.ts     Tests npm, PyPI, OCI, PURL et CycloneDX
  rendered-html.test.mjs   Tests du rendu de production
public/
  og.png         Carte d’aperçu du projet
```

## Scripts

| Commande | Usage |
| --- | --- |
| `npm run dev` | Démarre l’application en développement |
| `npm run build` | Produit et valide la version de production |
| `npm run start` | Lance la version construite |
| `npm run collect` | Produit un inventaire local assaini |
| `npm run collect:sbom` | Produit l’inventaire et le SBOM CycloneDX |
| `npm run collect -- --probe` | Ajoute une négociation passive des endpoints HTTPS |
| `npm run lint` | Vérifie les règles de qualité du code |
| `npm run test:unit` | Teste le moteur, le collecteur et la non-divulgation des secrets |
| `npm run test:rendered` | Vérifie le HTML produit par l’application |
| `npm test` | Construit puis exécute l’ensemble des tests |

## Intégration continue

Le workflow GitHub Actions `.github/workflows/ci.yml` s’exécute sur chaque pull
request et chaque mise à jour de `main`. Le collecteur et le moteur sont testés
sur Linux, Windows et macOS. Un second job lance le lint, construit
l’application et vérifie le HTML produit.

## Limites actuelles

- la découverte doit être lancée explicitement sur chaque poste à inventorier ;
- par sécurité, le collecteur n’exécute pas les serveurs `stdio` et ne confirme
  donc pas leur comportement à l’exécution ;
- le probe distant valide la négociation, pas les permissions effectives de
  chaque outil ;
- le SBOM décrit les composants directement visibles dans les commandes ; il
  ne résout pas encore leurs dépendances transitives et n’interroge aucun
  registre de vulnérabilités ;
- elle ne confirme pas les permissions effectives côté GitHub, base de données,
  OAuth ou système de fichiers ;
- l’historique affiché est illustratif et n’est pas encore persistant ;
- le catalogue de règles devra évoluer avec les spécifications et pratiques MCP.

## Prochaines étapes possibles

- enrichissement du SBOM avec les dépendances transitives et les avis OSV ;
- gestion d’exceptions documentées et datées ;
- export d’un rapport PDF ;
- historique persistant et suivi des écarts dans le temps ;
- intégration CI pour bloquer les configurations à haut risque.

## Contribution

Les contributions peuvent être proposées dans une branche dédiée avec :

1. une description du risque ou du contrôle ajouté ;
2. un exemple de configuration vulnérable et corrigée sans véritable secret ;
3. la validation de `npm run build` ;
4. une pull request expliquant les éventuels faux positifs.
