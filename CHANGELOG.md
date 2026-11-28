# Changelog

Toutes les modifications notables de ce projet sont documentées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet respecte le [Versionnage sémantique](https://semver.org/lang/fr/) :
`MAJEUR.MINEUR.CORRECTIF`, tags Git `vX.Y.Z` identiques à la version de `Cargo.toml`.

## [Non publié]

## [0.3.0] - 2026-11-28

### Ajouté
- Nouvelle interface conforme à la charte Rusty Suite : menu latéral réductible avec
  icônes, barre d'outils, barre d'état (réseau, langues, mise à jour), notifications,
  logo animé qui suit les tâches de fond, navigation clavier (Alt+1 à Alt+5, F6, F1).
- Mise à jour automatique avec contrôle SHA-256 et retour à la version précédente si la
  nouvelle ne démarre pas.
- Instance unique : un clic droit « Signer » sur d'autres fichiers les ajoute à la
  fenêtre déjà ouverte.
- Journal de l'application avec rotation et rapport de plantage.

### Modifié
- Programme portable : données dans `rusty_seal-data` à côté de l'exécutable. Un ancien
  dossier (`%APPDATA%
usty-suite
usty-seal` ou `~/rusty-seal`) contenant des coffres
  reste utilisé, sans perte de données.
- Langue choisie depuis la fenêtre Langue commune (l'ancien choix est repris) ; packs mis
  à jour depuis GitHub seulement s'ils sont aussi récents que le programme.

## [0.2.0] - 2026-11-28

### Modifié
- Licence : GNU GPL v3 ou ultérieure (`GPL-3.0-or-later`) à la place de PolyForm Noncommercial 1.0.0. Le programme devient un logiciel libre, utilisable par tous.

## [0.1.1] - 2026-11-27

### Corrigé
- Licence déclarée dans `Cargo.toml` : PolyForm Noncommercial 1.0.0 (comme le fichier de licence du dépôt), au lieu de MIT.

## [0.1.0] - 2026-11-26

Première release publique.

### Ajouté
- Signature de fichiers : Authenticode (PE, scripts PowerShell) et signature détachée JSON (`.sig`).
- Vérification des signatures, avec métadonnées et détails du certificat.
- Coffres-forts chiffrés (`.rsvc`) : plusieurs coffres, ajout, renommage, suppression confirmée,
  verrouillage automatique, changement de mot de passe, import / export.
- Gestion des certificats (création RSA / ECDSA / Ed25519, import / export PEM et DER).
- Profils de signature avec certificats compatibles et métadonnées.
- Signature rapide depuis le menu contextuel Windows (`--sign`), avec barre de progression.
- Journal d'audit avec contrôle d'intégrité et export JSON / CSV.
- Interface en 7 langues (EN, FR, DE, IT, CH-fr, CH-de, CH-it) intégrées au binaire ;
  le choix de langue est mémorisé ; repli automatique sur l'anglais pour toute clé manquante.
- Messages d'erreur traduits.
- Tests garantissant que toutes les langues ont les mêmes clés et que chaque clé utilisée existe.

[Non publié]: https://github.com/rusty-suite/rusty_seal/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/rusty-suite/rusty_seal/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/rusty-suite/rusty_seal/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/rusty-suite/rusty_seal/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/rusty-suite/rusty_seal/releases/tag/v0.1.0
