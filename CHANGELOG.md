# Changelog

Toutes les modifications notables de ce projet sont documentées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/)
et le projet respecte le [Versionnage sémantique](https://semver.org/lang/fr/) :
`MAJEUR.MINEUR.CORRECTIF`, tags Git `vX.Y.Z` identiques à la version de `Cargo.toml`.

## [Non publié]

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

[Non publié]: https://github.com/rusty-suite/rusty_seal/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/rusty-suite/rusty_seal/releases/tag/v0.1.0
