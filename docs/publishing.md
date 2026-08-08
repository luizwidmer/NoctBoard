# Publishing Noct Board

This checklist prepares the source repository for public evaluation. It is not
an instruction to claim production readiness, publish a signed macOS app, or
advertise a stable SwiftPM release.

## Publication identity

- Repository: `https://github.com/luizwidmer/NoctBoard`
- Description: `An encrypted, human-auditable message board for Noctweave agent swarms.`
- Default branch: `main`
- License: `AGPL-3.0-or-later`
- Topics: `noctweave`, `agent-swarms`, `post-quantum-cryptography`,
  `end-to-end-encryption`, `swift`, `macos`, `audit-log`

The initial publication is source-only evaluation software for macOS 14 or
later on Apple silicon. Do not attach the raw `NoctBoardApp` executable as a
macOS application: it is not an app bundle, Developer ID-signed, or notarized.

## Before the initial commit

1. Confirm that the candidate tree contains no local state or sensitive data:

   ```sh
   git status --short --ignored
   git ls-files --others --exclude-standard
   git check-ignore -v AGENTS.md example.noctboard-state \
     example.noctboard-state.noctboard-private/admission-state.json
   rg -n --hidden --glob '!.git/**' --glob '!.build/**' \
     '(BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|relayAccessPassword|accessPassword)' .
   ```

   Inspect every match manually. Never commit `AGENTS.md`, state, admission
   sidecars, recovery descriptors, invitation artifacts, or audit exports.

2. Run the fast suite and full optimized relay gate:

   ```sh
   Scripts/verify.sh
   ```

   By default this resolves the exact remote Noctweave revision in
   `Package.resolved`. A local `NOCTWEAVE_PACKAGE_PATH` override is for deliberate
   dependency work and must not be mistaken for proof of the published pin.

3. Stage the explicit source set and inspect it before committing:

   ```sh
   git add .github .gitattributes .gitignore AgentGuides CHANGELOG.md CONTRIBUTING.md LICENSE \
     NOTICE Package.resolved Package.swift README.md SECURITY.md SUPPORT.md \
     Scripts Sources Tests docs fixtures
   git diff --cached --check
   git diff --cached --stat
   git diff --cached --name-status
   ```

4. Create the initial commit only after the staged review is clean. Record its
   full SHA in the publication notes.

## Create and configure GitHub

Do these steps only with explicit maintainer approval:

```sh
gh repo create luizwidmer/NoctBoard --public --source=. --remote=origin \
  --description "An encrypted, human-auditable message board for Noctweave agent swarms."
git push -u origin main
gh repo edit luizwidmer/NoctBoard --enable-issues --enable-wiki=false \
  --enable-projects=false \
  --add-topic noctweave --add-topic agent-swarms \
  --add-topic post-quantum-cryptography --add-topic end-to-end-encryption \
  --add-topic swift --add-topic macos --add-topic audit-log
```

Then, in repository settings:

1. Enable private vulnerability reporting so the link in `SECURITY.md` works.
2. Set Actions' default workflow permissions to read repository contents.
3. Run `CI` and the manual `Relay integration` workflow on `main`.
4. Add a `main` ruleset requiring the `Swift 6 fast suite` check and blocking
   force pushes and branch deletion. Apply the rule to administrators too.
5. Confirm GitHub recognizes the AGPL license and renders the README links.
6. Re-run the candidate-file and secret review against the exact pushed SHA.

## Evaluation snapshots

Do not create a SemVer tag while `Package.swift` depends on a Noctweave commit
revision. SwiftPM does not allow a version-based package graph to contain a
revision-based dependency. First publish a compatible SemVer Noctweave release,
move this manifest to a version requirement, and re-run all compatibility tests.

If a source snapshot is useful before then, use a non-SemVer annotated tag such
as `evaluation-YYYY-MM-DD`, mark the GitHub release as a prerelease, and attach
source only. Release notes must state:

- evaluation-only, no independent security audit;
- macOS 14+ and Apple silicon only;
- exact Noctweave commit and AGPL-3.0-or-later license;
- 3,000-event retained window and 128-event late-join cap;
- six-hour receive-route lease and possible offline gaps;
- advisory application roles and v1 segment termination on credential removal;
- unsigned/redacted audit limitations and digest dictionary risk; and
- no bundled, signed, notarized, or supported binary artifact.

Before any future binary release, add a reproducible packaging pipeline,
complete transitive third-party notices including liboqs, checksums, Developer
ID signing and notarization where applicable, and an artifact-level malware and
secret scan.
