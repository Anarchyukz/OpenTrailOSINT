# OpenTrail OSINT

OpenTrail OSINT is an Android toolkit for lawful, public-source research. Notes are stored locally on the device.

## Tools
- Public web search, including queries for publicly indexed Facebook pages/posts
- URL triage (parses the URL locally; does not visit the target)
- DNS hostname lookup using Android's system resolver
- SHA-256 hashing of entered text
- Local case notes

## Build
GitHub Actions builds a debug APK on pushes to `main`. Download it from the workflow run's **Artifacts** section.

## Responsible use
Use public information and systems you are authorised to investigate. This app does not bypass logins or access private accounts. URL and DNS checks are triage aids, not proof that something is safe.

Kotlin, Jetpack Compose, local-first; no account or analytics required.
