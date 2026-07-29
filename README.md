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
- export d’un rapport JSON ou SARIF exploitable par les outils de sécurité ;
- vues dédiées aux serveurs, règles et audits ;
- interface responsive et accessible au clavier.

## Confidentialité

L’analyse est effectuée dans le navigateur :

- aucune configuration importée n’est envoyée à un service distant ;
- les valeurs sensibles détectées ne sont jamais affichées ;
- aucun secret n’est enregistré dans le stockage du navigateur ;
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

## Contrôles de sécurité

| Famille | Ce qui est vérifié | Exemple de correction |
| --- | --- | --- |
| Secrets | Jetons, mots de passe et clés présents en clair | Injection par variable d’environnement ou coffre de secrets |
| Transport | URL HTTP et absence d’authentification visible | HTTPS et jeton court lié à l’audience |
| Exécution | Shells intermédiaires et options désactivant la sécurité | Appel direct du binaire et sandbox active |
| Supply chain | Paquets `latest` ou non versionnés | Version exacte revue et verrouillée |
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
tests/
  audit-engine.test.ts     Tests de sécurité du moteur
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
| `npm run lint` | Vérifie les règles de qualité du code |
| `npm run test:unit` | Teste le moteur d’audit et la non-divulgation des secrets |
| `npm run test:rendered` | Vérifie le HTML produit par l’application |
| `npm test` | Construit puis exécute l’ensemble des tests |

## Intégration continue

Le workflow GitHub Actions `.github/workflows/ci.yml` s’exécute sur chaque pull
request et chaque mise à jour de `main`. Il installe les dépendances, lance le
lint, construit l’application et exécute les tests du moteur ainsi que du HTML
rendu.

## Limites actuelles

- l’application ne découvre pas automatiquement les configurations présentes
  sur d’autres postes ;
- elle ne contacte pas les serveurs MCP et ne vérifie donc pas leur comportement
  réel ;
- elle ne confirme pas les permissions effectives côté GitHub, base de données,
  OAuth ou système de fichiers ;
- l’historique affiché est illustratif et n’est pas encore persistant ;
- le catalogue de règles devra évoluer avec les spécifications et pratiques MCP.

## Prochaines étapes possibles

- connecteurs de découverte pour les gestionnaires MCP courants ;
- analyse de manifeste et SBOM des paquets exécutés ;
- tests réseau contrôlés avec autorisation explicite ;
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
