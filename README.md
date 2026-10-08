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
