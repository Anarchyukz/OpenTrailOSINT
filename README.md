# OpenTrail OSINT

OpenTrail OSINT is an Android toolkit for lawful, public-source research. It uses Kotlin and Jetpack Compose, keeps case notes locally, and does not require an account or analytics.

## Tools

- **Mr Holmes-style username research** across public search indexes for GitHub, Reddit, Facebook, Instagram, TikTok, X, YouTube, Pinterest, Twitch, Medium, Telegram, LinkedIn and Mastodon
- **Email OSINT** — public-index searches, public documents, GitHub and Gravatar mentions
- **Phone OSINT** — exact-number searches, public business listings, profile mentions and spam reports
- **Domain reconnaissance** — DNS resolution, certificate-transparency search, WHOIS/registration searches and public URL-scan references
- **IP lookup** — search shortcuts for public AbuseIPDB, VirusTotal, GreyNoise and reverse-DNS information
- **Public web search**, including publicly indexed Facebook pages/posts
- **URL triage** — local URL parsing for hostname, scheme, port, path, IP literals, punycode and user-info indicators
- **DNS lookup** — system DNS resolution
- **Encode/decode** — URL and Base64 transformations
- **Hash tools** — SHA-256, SHA-1 and MD5 of entered text, calculated locally
- **Local case notes** — saved on the device

## Build

GitHub Actions builds a debug APK on pushes to `main`. Download it from the workflow run's **Artifacts** section.

## Notes and responsible use

Many OSINT tools from existing GitHub projects (for example, username-search and reconnaissance frameworks) are command-line Python or server-side tools, not Android libraries. OpenTrail uses its own Kotlin implementation of compatible public-source workflows rather than copying whole codebases into the app. Check the original projects' licences before reusing their code.

Search shortcuts open external websites and rely on their public indexes; they do not scrape sites, bypass logins, or access private accounts. Search results may be incomplete or incorrectly attributed. DNS results reflect the current network and are not proof a domain is safe. Use public information and systems you are authorised to investigate.
