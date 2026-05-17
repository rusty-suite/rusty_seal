# Rusty Seal

<p align="center">
  <img src="assets/img/rusty-seal.png" width="120" alt="Rusty Seal logo"/>
</p>

> Signature de binaires, gestion de certificats et métadonnées — membre de la **Rusty Suite**.

---

## Fonctionnalités

### 🔐 Coffre-fort chiffré
- Chiffrement **AES-256-GCM** avec dérivation de clé **Argon2id**
- Second facteur optionnel par fichier-clé (XOR sur le mot de passe avant dérivation)
- Clés privées déchiffrées uniquement le temps d'une opération de signature, puis effacées de la mémoire (`zeroize`)
- Verrouillage automatique après une période d'inactivité configurable
- **Export** du coffre en archive chiffrée portable (`.rsvx`) avec mot de passe indépendant
- **Import** d'une archive `.rsvx` vers un nouvel emplacement
- Choix libre de l'emplacement du fichier coffre

### 📄 Gestion des certificats
| Action | Détails |
|--------|---------|
| Création auto-signée | Ed25519, ECDSA P-256, ECDSA P-384, RSA 2048, RSA 4096 |
| Import | PEM (`.pem`, `.crt`) — clé privée incluse si présente dans le fichier |
| Import | DER (`.cer`, `.der`) |
| Export | PEM ou DER du certificat public |
| Alias | Chaque certificat est référencé par un alias — remplacer un certificat ne modifie aucun profil |
| Expiration | Avertissements configurables (30, 7, 1 jours) + historique de remplacement par alias |

### 📁 Profils de signature
- Regroupe un **alias de certificat** et des **métadonnées par défaut**
- Plusieurs profils coexistent (par produit, par environnement…)
- Modifiable à tout moment sans affecter les signatures existantes

### ✍️ Signature de fichiers
- Sélection interactive de fichiers avec multi-sélection et filtre par nom
- Ajout de répertoires entiers (récursif via `walkdir`)
- Métadonnées intégrées : version, auteur, description, date de build, URL source, champs personnalisés
- Sortie : fichier détaché **`.sig`** (JSON signé) placé à côté du binaire
- **Signature par lot** de tous les fichiers sélectionnés en un clic

### 🔍 Vérification
- Comparaison du hash SHA-256 du fichier avec celui inscrit dans la signature
- Vérification cryptographique de la signature contre le certificat embarqué
- Affichage complet des métadonnées signées

### 📋 Journal d'audit
- Log append-only signé **HMAC-SHA256** (inviolabilité détectable)
- Enregistre : unlock, lock, création/import/suppression de certificat, signature, vérification
- Export **JSON** ou **CSV**

---

## Format des fichiers

### Coffre (`.rsvc`)
```
[4 B] magic "RSVC"
[1 B] version
[32 B] sel Argon2id
[12 B] nonce AES-GCM
[N B] payload = AES-256-GCM( gzip( JSON ) )
```

### Export coffre (`.rsvx`)
Même structure avec magic `RSVX` — le payload est le fichier `.rsvc` brut re-chiffré avec le mot de passe d'export.

### Signature (`.sig`)
```json
{
  "version": 1,
  "algorithm": "Ed25519",
  "cert_alias": "mon-cert",
  "cert_fingerprint": "SHA256:AA:BB:...",
  "file_hash": "SHA256:cc:dd:...",
  "file_name": "programme.exe",
  "signed_at": "2026-05-17T22:00:00Z",
  "metadata": {
    "version": "1.0.0",
    "author": "Acme Corp",
    "description": "...",
    "build_date": "2026-05-17",
    "source_url": "https://github.com/...",
    "custom": { "env": "production" }
  },
  "signature_b64": "base64...",
  "certificate_pem": "-----BEGIN CERTIFICATE-----..."
}
```

---

## Répertoire de travail

| Situation | Répertoire utilisé |
|-----------|-------------------|
| Installé via `suite_install` | `%APPDATA%\rusty-suite\rusty-seal\` |
| Mode autonome | `%USERPROFILE%\rusty-seal\` |

---

## Langues

Les fichiers de langue sont des TOML dans le sous-dossier `lang/` du répertoire de travail.

| Fichier | Langue |
|---------|--------|
| `EN_en.default.toml` | Anglais (défaut, embarqué dans le binaire) |
| `FR_fr.toml` | Français |

Convention de nommage : `PAYS_langue.toml` (ex. `CH_fr.toml`, `US_en.toml`).  
Si aucun fichier n'est trouvé localement, le programme tente de télécharger `EN_en.default.toml` depuis GitHub.

---

## Stack technique

| Composant | Crate |
|-----------|-------|
| Interface graphique | `eframe` / `egui` 0.29 |
| Chiffrement vault | `aes-gcm` 0.10 + `argon2` 0.5 |
| Signatures crypto | `ring` 0.17 (Ed25519, ECDSA, RSA) |
| Génération certificats | `rcgen` 0.13 |
| Parsing X.509 | `x509-parser` 0.16 |
| Parsing PEM | `pem` 3 |
| Police emoji | Segoe UI Emoji (système) |
| Sérialisation | `serde_json`, `toml` |
| Compression | `flate2` (gzip) |
| Audit HMAC | `hmac` + `sha2` |

---

## Structure du projet

```
rusty_seal/
├── assets/
│   └── img/
│       └── rusty-seal.png      # Icône de l'application
├── lang/
│   ├── EN_en.default.toml      # Langue par défaut (embarquée)
│   └── FR_fr.toml
└── src/
    ├── main.rs
    ├── app.rs                  # AppState + RustySealApp (eframe)
    ├── error.rs
    ├── workdir.rs              # Détection répertoire de travail Rusty Suite
    ├── i18n.rs                 # Chargement TOML + fallback GitHub
    ├── vault/
    │   ├── mod.rs              # Opérations coffre (unlock, save, export…)
    │   ├── crypto.rs           # AES-GCM, Argon2id
    │   └── types.rs            # VaultData, CertEntry, Profile, SigningMetadata
    ├── cert/
    │   └── mod.rs              # Génération, import PEM/DER, export, fingerprint
    ├── signing/
    │   ├── mod.rs              # sign_file, verify_signature
    │   └── format.rs           # SignatureFile (sérialisation .sig)
    ├── audit/
    │   └── mod.rs              # AuditLog, AuditEntry, HMAC, export CSV/JSON
    ├── profile/
    │   └── mod.rs
    └── ui/
        ├── mod.rs
        ├── theme.rs            # Couleurs Rusty Suite + chargement police emoji
        ├── vault_panel.rs
        ├── cert_panel.rs
        ├── profile_panel.rs
        ├── sign_panel.rs
        ├── verify_panel.rs
        └── audit_panel.rs
```

---

## Licence

PolyForm Noncommercial
