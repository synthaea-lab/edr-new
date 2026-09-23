# Objectifs Linux - Issues prioritaires non assignées

## Issue #90 - Build sensor-linux-uprobes: TLS plaintext taps + shell readline

**Labels:** new-dev, sensor
**Créée:** 2026-09-03
**Composant:** `crates/sensors/linux/uprobes`

### Description

Capturer le contenu TLS en clair et les commandes shell interactives via uprobes BPF.

- **TLS plaintext taps:** Instrumentation des fonctions SSL_read/SSL_write sur OpenSSL, BoringSSL et GnuTLS pour capturer le contenu C2 pré-chiffrement
- **Shell readline:** Interception des commandes interactives bash/zsh (via readline) pour capturer les commandes qui ne passent pas par execve
- Résolution de symboles par binaire, tracking à travers les mises à jour de bibliothèques
- Budget imposé : premiers N octets, allowlist de processus (comm)
- Ajout d'un nouveau type d'événement dans le schéma pour le contenu capturé (additive)

### Critères de complétion

- [ ] Lab: Une requête HTTPS curl (beacon) capture la ligne de requête en clair et l'attribue correctement
- [ ] Les commandes shell interactives (builtins sans execve) apparaissent comme événements
- [ ] Budget documenté et appliqué (caps bytes/proc/sec)

### Notes techniques

Les programmes de probe rejoignent le build de la crate ebpf. Voir la documentation de la crate pour les détails d'implémentation.

---

## Issue #36 - Packaging: Linux (deb/rpm + systemd)

**Labels:** new-dev, ops
**Créée:** 2026-09-03
**Composant:** `packaging/linux`

### Description

Créer les packages Linux natifs avec intégration systemd complète.

- **Formats:** deb (Debian/Ubuntu) + rpm (RHEL/Fedora/etc.)
- **Systemd units:** Services pour agent + watchdog
- **Configuration système:** sysusers.d, tmpfiles.d
- **Installation propre:** Désinstallation complète sans résidus
- Consommé par le provisioning lab (agent-install)

### Critères de complétion

- [ ] Install/uninstall propre sur la matrice de VMs Debian + RPM
- [ ] Les services survivent au reboot

### Notes techniques

Les packages doivent respecter les conventions de chaque distribution (FHS, politiques Debian/Fedora) et permettre une désinstallation complète sans laisser de traces.

---

## Issue #34 - Build Linux audit fallback sensor

**Labels:** new-dev, sensor
**Créée:** 2026-09-03
**Composant:** `crates/sensors/linux/audit`

### Description

Sensor de secours pour les hosts sans eBPF, basé sur auditd et fanotify.

- **auditd netlink:** Capture execve et connect
- **fanotify:** Surveillance des fichiers
- **Réduction de fidélité attendue:** La perte de capacités par rapport à eBPF est mesurée par conformance et documentée explicitement (pas cachée)
- Permet le déploiement sur des kernels plus anciens ou des environnements où eBPF n'est pas disponible

### Critères de complétion

- [ ] Contrat sensor implémenté
- [ ] Scénarios exécutés sur une VM de la matrice avec eBPF désactivé
- [ ] La sortie conformance montre le delta exact de capacités vs eBPF

### Notes techniques

La réduction de fidélité est un compromis accepté et mesuré. Le système de conformance doit explicitement documenter quelles capacités sont perdues par rapport à l'implémentation eBPF complète.

---

## Prioritisation suggérée

1. **#90 (uprobes)** - Capacité de détection avancée pour C2 chiffré et commandes shell furtives
2. **#36 (packaging)** - Bloquant pour le déploiement production sur Linux
3. **#34 (audit fallback)** - Élargirait la compatibilité kernel mais moins critique si eBPF est disponible

Toutes ces issues sont actuellement **non assignées** et disponibles pour être prises en charge.
