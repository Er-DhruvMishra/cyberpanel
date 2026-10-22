# CyberPanel Universal

A fork of [usmannasir/cyberpanel](https://github.com/usmannasir/cyberpanel) that installs and
upgrades on any apt- or dnf/yum-based Linux, including CentOS 8, where current upstream
releases no longer work.

This tree is upstream `stable` (v3.0.8, 2026-10-21) plus the unreleased fixes from upstream's
`v3.0.5-dev` (ported 2026-10-23), plus a small, isolated compatibility layer. Upstream
features and fixes are kept as-is. When something conflicts with a host, it is switched off on
that host instead of failing the install.

## Install / upgrade

```bash
# fresh install
sh <(curl -fsSL https://raw.githubusercontent.com/Er-DhruvMishra/cyberpanel/main/install.sh)


# upgrade an existing panel (upstream or this fork)
sh <(curl -fsSL https://raw.githubusercontent.com/Er-DhruvMishra/cyberpanel/main/preUpgrade.sh)
```

All installer options are unchanged from upstream (`cyberpanel.sh -h`). You can also set:

| variable | effect |
|---|---|
| `CYBERPANEL_OS_PROFILE="CentOS 8"` | force a profile instead of auto-detecting it |
| `CYBERPANEL_GIT_USER=name` | install from another GitHub account's `cyberpanel` repo |
| `CYBERPANEL_BRANCH=name` | install/upgrade from a branch other than `main` |

## Why upstream broke on CentOS 8

1. **Python.** CentOS 8's `python3` is 3.6. Current upstream needs Django 4.2, fastapi,
   uvicorn and websockets 15, which all require Python 3.9 or newer. Upstream still builds
   the panel virtualenvs on `/usr/bin/python3`.
2. **Requirements file.** The EL8 and Ubuntu 20 profiles download `requirments-old.txt`,
   which pins Django 3.1.3. The current code no longer runs on that.
3. **lscpd runtime.** `lswsgi` was linked against `libpython3.6m`, and `pythonenv.conf` points
   lscpd at system Python (`PYTHONHOME=/usr`). That system Python cannot run the new
   requirements.

## What the compatibility layer does

| piece | where |
|---|---|
| Maps the host onto the nearest upstream OS profile (`Server_OS`/`Server_OS_Version`). Records it in `/etc/cyberpanel/os_profile`. | `universal/compat.sh` (`Universal_Detect_OS`), embedded in `cyberpanel.sh` and `cyberpanel_upgrade.sh` |
| The same mapping for Python. `decideDistro`, `install_utils.get_distro` and `Upgrade.FindOperatingSytem` fall back to it for releases upstream does not recognise. | `cyberpanel_os_profile.py` |
| Picks a Python between 3.9 and 3.12 for the virtualenvs, installing one if needed (EL8: `python39`; Debian/Ubuntu: `python3.X` or deadsnakes). | `Universal_Select_Python` |
| Always uses `requirments.txt` when that Python is available. | `Download_Requirement` (both scripts) |
| Builds `lswsgi` against that Python. Writes `pythonenv.conf` with `PYTHONHOME=<base prefix>` and `PYTHONPATH=<CyberCP venv>`, so system Python is never modified. | `Universal_Configure_LSCPD_Env` |
| Upgrades rebuild a CyberCP virtualenv whose Python is out of range (an existing CentOS 8 install on 3.6). | `Main_Upgrade` |

Natively supported hosts (upstream's own list, with a usable system Python) keep upstream's
exact code paths. The layer only changes behaviour when it has to.

### Profile mapping

| host | profile |
|---|---|
| CentOS / RHEL / Alma / Rocky / CloudLinux / Oracle / Stream / other EL-likes 7–10 | CentOS 7–10 (11+ → 10) |
| Fedora 28–33 / 34–39 / 40+ | CentOS 8 / 9 / 10 |
| Amazon Linux 2 / 2023 | CentOS 7 / 9 |
| Ubuntu (non-LTS → previous LTS) | Ubuntu 18–26 |
| Ubuntu derivatives (Mint, Pop!_OS, …) | Ubuntu, chosen by `UBUNTU_CODENAME` |
| Debian ≤11 / 12 / 13+ and derivatives | Ubuntu 20 / 22 / 24 |
| openEuler 20.03 / 22.03 (+ newer) | openEuler 20 / 22 |
| anything else with apt / dnf / yum | Ubuntu 22 / CentOS 9 / CentOS 7 |

### Features disabled on conflicting hosts

These are recorded in `/etc/cyberpanel/disabled_features` and in `/var/log/cyberpanel_universal.log`.

| feature | disabled when | why |
|---|---|---|
| `custom_ols`: CyberPanel's custom OpenLiteSpeed/ModSecurity build | host is not on upstream's list | the binaries are built for specific glibc/ABI targets. Stock OpenLiteSpeed from LiteSpeed's repo is used instead. |
| `high_availability` | host is not Ubuntu | `highAvailability/haManager.py` only implements Ubuntu (upstream limitation) |

CentOS 8 is a native profile, so it keeps the custom OLS build and every other feature.

## Fixes carried on top of upstream

- **cpecs (email limits policy daemon)** never answered Postfix under Python 3 (bytes/str), so
  per-mailbox sending limits were silently not enforced. Its unit file also left no running
  process. Fixed in `postfixSenderPolicy/` and `cpecs.service`; enabling limits replaces the
  legacy unit.
- `dockerManager/container.py`: `is ''` changed to `== ''`.
- `install/install_utils.get_distro`: fixed an upstream bug where
  `data.find('CloudLinux 8')` was always truthy.

## Releasing

Installs, upgrades and the panel's "new version" check all track **`main`** on
github.com/Er-DhruvMishra/cyberpanel (`Universal_Release_Branch` in `universal/compat.sh`,
`RELEASE_BRANCH` in `cyberpanel_version.py`). Pushing to `main` releases it:

```bash
git push origin main
```

The fork's other branches (`stable`, `v3.0.x`, `v3.0.5-dev`, …) are plain mirrors of
usmannasir/cyberpanel and are not used by the installer. `-b 3.0.8` or
`CYBERPANEL_BRANCH=v3.0.8` still installs a specific branch, but those branches carry no
compatibility layer.

Keep `version.txt` and `cyberpanel_version.py` in step with upstream's numbering. The panel
shows them, and uses them for its internal upgrade gates.

## Pulling new upstream fixes

```bash
git fetch upstream
git merge upstream/stable          # or the new upstream release branch, e.g. upstream/v3.0.9
git log --oneline main..upstream/v3.0.5-dev   # upstream's dev line: unreleased fixes
tools/sync-compat.sh               # re-embed universal/compat.sh if the scripts changed
python3 universal/tests/test_os_profile.py
bash -n cyberpanel.sh && bash -n cyberpanel_upgrade.sh
```

Conflicts, if any, will be in the few `# Universal:` hunks of `cyberpanel.sh`,
`cyberpanel_upgrade.sh`, `install.sh`, `preUpgrade.sh`, and the three Python detectors.
`git grep -n "Universal"` lists all of them.

Upstream keeps `stable` and its dev branch (GitHub's default, `v3.0.5-dev`) apart, and many
dev fixes reach `stable` later in reworked form. Cherry-pick dev commits one by one rather
than merging the branch. Skip any whose subject already exists in `stable`
(`git log --oneline -F --grep="<subject>" upstream/stable`). Then record the branch with
`git merge -s ours upstream/v3.0.5-dev`, so GitHub stops reporting `main` as behind.

After a merge, re-check two things:
- `git grep -n "usmannasir/cyberpanel"` for new upstream download URLs that should point at
  the fork. Leave issue links alone.
- Any new `requirments.txt` pins that need a Python newer than 3.9. If upstream raises the
  floor, bump `Universal_Min_Python`.

## Universal Add-ons

Our own open-source modules, in `universalAddons/` (sidebar: **Universal Add-ons**, administrators
only). They are independent of upstream's paid add-ons: they do not use or bypass upstream's
licence checks and never contact cyberpanel.net.

| module | status |
|---|---|
| Email Debugger | ready |
| Root File Manager | ready |
| Rspamd Manager | ready |
| SSL V2 | in development |
| Backup V2 | in development |
| WordPress Manager Pro | in development |
| .htaccess for OpenLiteSpeed | in development |

**Email Debugger** covers:
- DNS checks (MX, SPF, DKIM, DMARC, PTR) and blocklists;
- ports and TLS certificates;
- Postfix message tracing;
- the mail queue;
- spam scores;
- test messages.

**Root File Manager** covers:
- trash with restore;
- an audit log at `/var/log/cyberpanel_rootfm.log`;
- protected paths, which need explicit confirmation;
- atomic saves;
- safe archive extraction.

The design, a review of the official modules and the roadmap are in `universalAddons/PLAN.md`.
Privileged work runs through one root runner (`universalAddons/runner.py`). Request data never
reaches a shell.

Tests: `python manage.py test universalAddons`. A database is not needed; use a SQLite settings
override.

## Status and known limitations

- **What has been verified, on the CentOS 8 production host (without installing anything system-wide):**
  - upstream `requirments.txt` installs and imports on Python 3.9;
  - `manage.py check` passes on 3.9;
  - every `.py` file parses on 3.9, and there are no 3.10+ runtime features;
  - `lswsgi` builds against 3.9, and the WSGI application boots with the generated
    `PYTHONHOME`/`PYTHONPATH`;
  - all three Python detectors return `cent8` on the host;
  - the profile mapping matches between shell and Python for 23 os-release fixtures
    (`universal/tests/`);
  - upstream's `install/test_*.py` results are identical to unmodified upstream.
- **Not yet run end-to-end:** a full install or upgrade, on any distro. Do the first run on
  a disposable CentOS 8 VM, then on a snapshot of a production server.
- **Hosts whose only Python is 3.13 or newer, with no 3.9–3.12 package** (for example
  Debian 13 without backports, Fedora 41+): the installer stops with a clear message. Install
  e.g. `python3.12` + `-venv`/`-devel` and re-run. Django 4.2 does not support 3.13+.
- Upstream's China (gitee) source mirror is not used. CN servers clone from GitHub; package
  mirrors are unchanged.

## Branches

- `main`: upstream stable + dev fixes + this layer. Installs and upgrades use it.
- `stable`, `v3.0.x`, `v3.0.5-dev`, …: mirrors of upstream, kept in sync by hand
- `legacy-2.3.4`: snapshot of the production CentOS 8 server's CyberPanel 2.3.4 and its local
  patches, for reference and rollback
