# Anonymise

Atelier de détection et d'anonymisation **entièrement local**. Ouvrir [l'application GitHub Pages](https://angstik.github.io/anonymise/).

## Fonctionnement
- Fichiers TXT, LOG, JSON, JSONL, XML, CSV, TSV (et formats texte génériques).
- Analyse heuristique des données personnelles et secrets, avec inspection et correction manuelle.
- Anonymisation par remplacement des seules plages identifiées pour conserver le formatage et la structure autant que possible.
- Rapport JSON des zones et traitements **sans divulgation des valeurs d'origine**.
- PWA avec service worker hors ligne; aucun fichier transmis au réseau.

## Limites de sécurité
Les détecteurs sont heuristiques : faux positifs et faux négatifs sont possibles. Toujours relire et tester les exports avant diffusion. Les occurrences superposées sont arbitrées au profit du détecteur le plus spécifique. La détection d'encodage sans BOM ne peut être parfaite, notamment pour les variantes mono-octet; le format retenu s'affiche. Seuls UTF-8, UTF-16LE/BE, Windows-1252 et ISO-8859-1 sont réencodés. Le masquage conserve la longueur en caractères et la ponctuation typique, mais peut rendre non valides certains contrôles métier ou signatures. Dans le cas des noms de clés sensibles et de structures imbriquées complexes, les localisateurs produits sont indicatifs; les **offsets** restent la référence pour restaurer les zones dans la source identique. Ne considérez jamais ce traitement heuristique comme une garantie de conformité RGPD.

## Développement
Aucune compilation : serveur statique à la racine, ex. `python3 -m http.server 8080` (pour tester le scope Pages, servir depuis un répertoire `/anonymise/`). `node --check app.js` et `node --check sw.js` contrôlent la syntaxe. Chaque push sur `main` déclenche le déploiement Pages.

## Licence
Aucune licence spécifiée.

## Office v1.1
DOCX et XLSX sont lus et écrits localement via ZIP/OOXML. Les textes Word, les cellules des feuilles Excel et les chaînes partagées sont analysés. Les segments XML peuvent être fragmentés et les formules ne sont pas analysées. DOC et XLS binaires ne sont pas pris en charge. CompressionStream et DecompressionStream deflate-raw sont requis. Vérifier les fichiers exportés dans les applications Office.

## v1.2
Détection et anonymisation automatiques; correction manuelle possible. Pseudonymisation déterministe locale non cryptographique. La propagation manuelle cible les valeurs identiques dans les éléments structurels repérés. Les chemins restent heuristiques pour certains formats complexes.

## v1.3
Un sel aléatoire prérempli, modifiable et non sauvegardé est demandé à l’ouverture; sauvegardez-le séparément pour reproduire les substitutions. La pseudonymisation demeure non cryptographique. L'export demande confirmation et compte les règles et occurrences marquées « conserver ». En JSON, les chemins et indices de tableaux sont analysés avec offsets source. En CSV, les champs échappés et les sauts de ligne entre guillemets sont analysés. Certaines transformations peuvent violer des contraintes de schéma, nécessitant vérification.

## XLSX v1.4
Les feuilles XLSX sont affichées comme tableaux (colonnes, en-têtes de la première ligne renseignée et références de cellules). Les groupes d’anonymisation s’appliquent par feuille et colonne; sélectionner une cellule peut révéler sa zone. Les cellules de formules ne sont pas modifiées et certaines particularités OOXML restent non couvertes (tables pivot, dates de nombres formatés, contenus liés). Lors d’un export, seule la cellule modifiée est réécrite; une chaîne partagée utilisée par plusieurs cellules n’est pas modifiée globalement. Le bouton Fermer le fichier libère les données du document courant.
