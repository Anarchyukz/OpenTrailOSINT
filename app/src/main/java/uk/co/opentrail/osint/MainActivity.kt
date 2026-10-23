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
    HOLMES("Mr Holmes"), SEARCH("Public search"), URL("URL triage"), DNS("DNS lookup"), HASH("SHA-256"), NOTES("Case notes")
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
                        OutlinedTextField(value = input, onValueChange = { input = it }, modifier = Modifier.fillMaxWidth(), label = { Text("Text to hash") }, minLines = 3)
                        Button(onClick = {
                            result = MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))
                                .joinToString("") { byte -> "%02x".format(byte) }
                        }, modifier = Modifier.fillMaxWidth()) { Text("Calculate SHA-256") }
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
