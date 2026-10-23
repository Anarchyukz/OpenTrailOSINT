package uk.co.opentrail.osint

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.URI
import java.security.MessageDigest

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { OpenTrailApp() }
    }
}

private enum class ToolTab(val title: String) {
    HOLMES("Mr Holmes"), SEARCH("Public search"), EMAIL("Email OSINT"), PHONE("Phone OSINT"), DOMAIN("Domain recon"), IP("IP lookup"), URL("URL triage"), DNS("DNS lookup"), ENCODE("Encode / decode"), HASH("Hash tools"), NOTES("Case notes")
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun OpenTrailApp() {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences("opentrail_local", Context.MODE_PRIVATE) }
    val scope = rememberCoroutineScope()
    var selected by remember { mutableStateOf(ToolTab.SEARCH) }
    var input by remember { mutableStateOf("") }
    var result by remember { mutableStateOf("") }
    var notes by remember { mutableStateOf(prefs.getString("notes", "") ?: "") }
    var noteDraft by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    MaterialTheme(colorScheme = darkColorScheme(
        primary = androidx.compose.ui.graphics.Color(0xFFFFB74D),
        secondary = androidx.compose.ui.graphics.Color(0xFF80CBC4)
    )) {
        Scaffold(topBar = {
            TopAppBar(title = {
                Column {
                    Text("OpenTrail OSINT", fontWeight = FontWeight.Bold)
                    Text("Public-source research toolkit", style = MaterialTheme.typography.labelSmall)
                }
            })
        }) { padding ->
            Column(
                modifier = Modifier.padding(padding).fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text("Tools", style = MaterialTheme.typography.titleMedium)
                ToolTab.entries.chunked(2).forEach { row ->
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                        row.forEach { item ->
                            FilterChip(
                                selected = selected == item,
                                onClick = { selected = item; input = ""; result = "" },
                                label = { Text(item.title) }
                            )
                        }
                    }
                }
                when (selected) {
                    ToolTab.HOLMES -> {
                        Text("Mr Holmes — username investigation", style = MaterialTheme.typography.titleLarge)
                        Text("Search public web indexes for a username or alias across multiple platforms. Each search opens in your browser; manually verify any matches.")
                        OutlinedTextField(
                            value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(),
                            label = { Text("Username or alias (without @)") }, singleLine = true
                        )
                        val username = input.trim().removePrefix("@")
                        val sites = listOf(
                            "General web" to "https://www.google.com/search?q=" + Uri.encode("\"$username\" (username OR profile)"),
                            "GitHub" to "site:github.com/$username",
                            "Reddit" to "site:reddit.com/u/$username OR site:reddit.com/user/$username",
                            "Facebook" to "site:facebook.com/$username",
                            "Instagram" to "site:instagram.com/$username",
                            "TikTok" to "site:tiktok.com/@$username",
                            "X / Twitter" to "site:x.com/$username OR site:twitter.com/$username",
                            "YouTube" to "site:youtube.com/@$username",
                            "Pinterest" to "site:pinterest.com/$username",
                            "Twitch" to "site:twitch.tv/$username",
                            "Medium" to "site:medium.com/@$username",
                            "Telegram public pages" to "site:t.me/$username",
                            "LinkedIn public results" to "site:linkedin.com/in/$username",
                            "Mastodon" to "\"$username\" site:mastodon.social OR site:fosstodon.org"
                        )
                        Button(onClick = {
                            if (username.isNotBlank()) {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + Uri.encode("\"$username\" (username OR profile)"))))
                            }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Search alias across the web") }
                        sites.drop(1).forEach { (label, query) ->
                            OutlinedButton(
                                onClick = {
                                    if (username.isNotBlank()) {
                                        context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + Uri.encode(query))))
                                    }
                                },
                                modifier = Modifier.fillMaxWidth()
                            ) { Text("Search $label") }
                        }
                        Text("A matching username is not proof that accounts belong to the same person. Search results depend on indexing; this does not access private accounts.")
                    }
                    ToolTab.EMAIL -> {
                        Text("Email address OSINT", style = MaterialTheme.typography.titleLarge)
                        Text("Search public indexes for an address or domain. These searches do not verify mailbox ownership or reveal private account data.")
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Email address or domain") }, singleLine = true)
                        val q = input.trim()
                        val emailQueries = listOf(
                            "General web" to "\\"$q\\"",
                            "Public paste results" to "\\"$q\\" (paste OR leaked OR exposed)",
                            "GitHub code and profiles" to "site:github.com \\"$q\\"",
                            "Public documents" to "\\"$q\\" (filetype:pdf OR filetype:doc OR filetype:xls)",
                            "Gravatar profile" to "site:gravatar.com \\"$q\\""
                        )
                        emailQueries.forEach { (label, query) ->
                            OutlinedButton(onClick = { if (q.isNotBlank()) context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + Uri.encode(query)))) }, modifier = Modifier.fillMaxWidth()) { Text("Search $label") }
                        }
                    }
                    ToolTab.PHONE -> {
                        Text("Phone number OSINT", style = MaterialTheme.typography.titleLarge)
                        Text("Use a full international format where possible. Search results may be stale or incorrectly attributed.")
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("+44… phone number") }, singleLine = true)
                        val q = input.trim()
                        listOf(
                            "Exact number" to "\\"$q\\"",
                            "Public business listings" to "\\"$q\\" (contact OR business)",
                            "Public social profiles" to "\\"$q\\" (profile OR contact)",
                            "Complaints / spam reports" to "\\"$q\\" (spam OR scam OR nuisance)"
                        ).forEach { (label, query) ->
                            OutlinedButton(onClick = { if (q.isNotBlank()) context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + Uri.encode(query)))) }, modifier = Modifier.fillMaxWidth()) { Text("Search $label") }
                        }
                    }
                    ToolTab.DOMAIN -> {
                        Text("Domain reconnaissance", style = MaterialTheme.typography.titleLarge)
                        Text("Passive checks and public-index searches only. Enter a hostname, not a full URL.")
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("example.com") }, singleLine = true)
                        val host = input.trim().removePrefix("https://").removePrefix("http://").substringBefore("/").substringBefore(":")
                        Button(enabled = !busy, onClick = {
                            if (host.isNotBlank()) {
                                busy = true
                                result = "Resolving $host…"
                                scope.launch {
                                    result = withContext(Dispatchers.IO) {
                                        runCatching {
                                            val addresses = InetAddress.getAllByName(host).joinToString("\\n") { it.hostAddress }
                                            "Domain: $host\\nResolved addresses:\\n$addresses\\n\\nThis is a DNS snapshot from your current network, not a security verdict."
                                        }.getOrElse { "DNS lookup failed: " + (it.message ?: "unknown error") }
                                    }
                                    busy = false
                                }
                            } else result = "Enter a domain first."
                        }, modifier = Modifier.fillMaxWidth()) { Text("Resolve domain") }
                        listOf(
                            "WHOIS / registration" to "https://www.google.com/search?q=" + Uri.encode("whois $host domain registration"),
                            "Certificate transparency" to "https://crt.sh/?q=" + Uri.encode("%.$host"),
                            "Public URL scan reports" to "https://www.google.com/search?q=" + Uri.encode("site:urlscan.io/domain/$host"),
                            "Public web mentions" to "https://www.google.com/search?q=" + Uri.encode("site:$host")
                        ).forEach { (label, url) ->
                            OutlinedButton(onClick = { if (host.isNotBlank()) context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }, modifier = Modifier.fillMaxWidth()) { Text(label) }
                        }
                    }
                    ToolTab.IP -> {
                        Text("IP address intelligence", style = MaterialTheme.typography.titleLarge)
                        Text("Opens public lookup services and search indexes; results may be incomplete. Do not treat reputation scores as proof.")
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("IPv4 or IPv6 address") }, singleLine = true)
                        val ip = input.trim()
                        listOf(
                            "General search" to "https://www.google.com/search?q=" + Uri.encode("\\"$ip\\""),
                            "AbuseIPDB public reports" to "https://www.google.com/search?q=" + Uri.encode("site:abuseipdb.com/check $ip"),
                            "VirusTotal public page" to "https://www.google.com/search?q=" + Uri.encode("site:virustotal.com/gui/ip-address $ip"),
                            "GreyNoise public context" to "https://www.google.com/search?q=" + Uri.encode("site:viz.greynoise.io $ip"),
                            "Reverse DNS" to "https://www.google.com/search?q=" + Uri.encode("\\"$ip\\" reverse DNS")
                        ).forEach { (label, url) ->
                            OutlinedButton(onClick = { if (ip.isNotBlank()) context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }, modifier = Modifier.fillMaxWidth()) { Text(label) }
                        }
                    }
                    ToolTab.ENCODE -> {
                        Text("Text encoders and decoders", style = MaterialTheme.typography.titleLarge)
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Input text") }, minLines = 3)
                        Button(onClick = { result = Uri.encode(input) }, modifier = Modifier.fillMaxWidth()) { Text("URL encode") }
                        OutlinedButton(onClick = { result = runCatching { Uri.decode(input) }.getOrElse { "Could not decode URL text: " + it.message } }, modifier = Modifier.fillMaxWidth()) { Text("URL decode") }
                        OutlinedButton(onClick = { result = android.util.Base64.encodeToString(input.toByteArray(Charsets.UTF_8), android.util.Base64.NO_WRAP) }, modifier = Modifier.fillMaxWidth()) { Text("Base64 encode") }
                        OutlinedButton(onClick = { result = runCatching { String(android.util.Base64.decode(input.trim(), android.util.Base64.DEFAULT), Charsets.UTF_8) }.getOrElse { "Invalid Base64 input." } }, modifier = Modifier.fillMaxWidth()) { Text("Base64 decode") }
                    }
                    ToolTab.SEARCH -> {
                        Text("Search publicly available information", style = MaterialTheme.typography.titleLarge)
                        OutlinedTextField(
                            value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(),
                            label = { Text("Name, username or keyword") }, singleLine = true
                        )
                        Button(onClick = {
                            if (input.isNotBlank()) {
                                val url = "https://www.google.com/search?q=" + Uri.encode(input.trim())
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                            }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Search the web") }
                        OutlinedButton(onClick = {
                            if (input.isNotBlank()) {
                                val q = Uri.encode("site:facebook.com " + input.trim())
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://www.google.com/search?q=" + q)))
                            }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Search publicly indexed Facebook pages/posts") }
                        Text("Searches open in your browser. Search engines only show content they have indexed; this does not access private content.")
                    }
                    ToolTab.URL -> {
                        Text("URL triage", style = MaterialTheme.typography.titleLarge)
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("https://example.com/path") })
                        Button(onClick = {
                            result = runCatching {
                                val raw = if (input.trim().contains("://")) input.trim() else "https://" + input.trim()
                                val uri = URI(raw)
                                val host = uri.host ?: error("Could not parse hostname. Check the URL.")
                                listOf(
                                    "Host: " + host,
                                    "Scheme: " + (uri.scheme ?: "unspecified"),
                                    "Port: " + if (uri.port == -1) "default" else uri.port.toString(),
                                    "Path: " + (uri.path.ifBlank { "/" }),
                                    "HTTPS: " + uri.scheme.equals("https", true),
                                    "IP literal: " + (host.matches(Regex("^[0-9.]+$")) || host.contains(":")),
                                    "Punycode present: " + host.contains("xn--", true),
                                    "User-info present: " + (uri.rawUserInfo != null),
                                    "",
                                    "Local parse only; no request was sent to the target."
                                ).joinToString("\n")
                            }.getOrElse { "URL error: " + (it.message ?: "invalid URL") }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Analyse URL") }
                    }
                    ToolTab.DNS -> {
                        Text("DNS hostname lookup", style = MaterialTheme.typography.titleLarge)
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("example.com") }, singleLine = true)
                        Button(enabled = !busy, onClick = {
                            busy = true
                            result = "Looking up…"
                            val host = input.trim()
                            scope.launch {
                                result = withContext(Dispatchers.IO) {
                                    runCatching {
                                        require(host.isNotBlank()) { "Enter a hostname first." }
                                        InetAddress.getAllByName(host).joinToString("\n") { address -> address.hostAddress }
                                    }.getOrElse { "Lookup failed: " + (it.message ?: "unknown error") }
                                }
                                busy = false
                            }
                        }, modifier = Modifier.fillMaxWidth()) { Text(if (busy) "Looking up…" else "Resolve hostname") }
                        Text("Uses Android's system resolver. Results can vary by network and DNS provider.")
                    }
                    ToolTab.HASH -> {
                        Text("SHA-256 text hash", style = MaterialTheme.typography.titleLarge)
                    }
                    ToolTab.NOTES -> {
                        Text("Local case notes", style = MaterialTheme.typography.titleLarge)
                        OutlinedTextField(value = noteDraft, onValueChange = { noteDraft = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Write a note") }, minLines = 3)
                        Button(onClick = {
                            if (noteDraft.isNotBlank()) {
                                notes = (notes + if (notes.isBlank()) "" else "\n\n" + "• " + noteDraft.trim()).trim()
                                prefs.edit().putString("notes", notes).apply()
                                noteDraft = ""
                            }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Save note on this device") }
                        if (notes.isNotBlank()) {
                            Card(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(12.dp)) {
                                    Text(notes)
                                    TextButton(onClick = {
                                        notes = ""
                                        prefs.edit().remove("notes").apply()
                                    }) { Text("Delete all notes") }
                                }
                            }
                        } else Text("No notes saved yet. Notes stay on this device.")
                    }
                }
                if (result.isNotBlank() && selected != ToolTab.NOTES) {
                    HorizontalDivider()
                    Text("Result", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp)) {
                            Text(result)
                            TextButton(onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                clipboard.setPrimaryClip(ClipData.newPlainText("OpenTrail result", result))
                            }) { Text("Copy result") }
                        }
                    }
                }
                HorizontalDivider()
                Text("Use responsibly", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                Text("For lawful public-source research only. URL and DNS results are triage aids, not a guarantee of safety. Do not target private accounts or access information without permission.")
            }
        }
    }
}
