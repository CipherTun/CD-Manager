package io.ciphertun.cdm

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.animation.core.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.documentfile.provider.DocumentFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) { super.onCreate(savedInstanceState); setContent { CDManagerApp() } }
}

@Composable
fun CDManagerApp() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var tab by remember { mutableIntStateOf(0) }
    var report by remember { mutableStateOf<FileReport?>(null) }
    var busy by remember { mutableStateOf(false) }
    var cryptoMode by remember { mutableStateOf<String?>(null) }
    var cryptoInput by remember { mutableStateOf<Uri?>(null) }
    var password by remember { mutableStateOf("") }
    var showPassword by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("") }
    val clipboard = LocalClipboardManager.current

    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            runCatching { context.contentResolver.takePersistableUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
            val name = DocumentFile.fromSingleUri(context, uri)?.name ?: uri.lastPathSegment?.substringAfterLast('/') ?: "selected file"
            busy = true
            scope.launch(Dispatchers.IO) {
                val result = runCatching { Analyzer.analyze(context.contentResolver, uri, name) }
                launch(Dispatchers.Main) {
                    report = result.getOrElse { error ->
                        FileReport(
                            name = name, size = -1L, extension = name.substringAfterLast('.', ""),
                            mime = "application/octet-stream", format = "Analysis failed",
                            confidence = 0, encrypted = false, sha256 = "",
                            adapterStatus = "Error", warnings = listOf(error.message ?: error.javaClass.simpleName)
                        )
                    }
                    busy = false; tab = 2
                }
            }
        }
    }
    val cryptoPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) cryptoInput = uri }
    val savePicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { outUri ->
        val inUri = cryptoInput ?: return@rememberLauncherForActivityResult
        if (outUri == null) return@rememberLauncherForActivityResult
        if (password.length < 8) { status = "Use a password of at least 8 characters."; return@rememberLauncherForActivityResult }
        busy = true; status = "Processing…"
        scope.launch(Dispatchers.IO) {
            val result = runCatching {
                context.contentResolver.openInputStream(inUri)!!.use { input ->
                    context.contentResolver.openOutputStream(outUri)!!.use { output ->
                        val pass = password.toCharArray()
                        try {
                            if (cryptoMode == "encrypt") CryptoEngine.encrypt(input, output, pass) else CryptoEngine.decrypt(input, output, pass)
                        } finally { pass.fill('\u0000') }
                    }
                }
            }
            launch(Dispatchers.Main) {
                busy = false
                status = result.fold({ "Completed successfully." }, { "Failed: ${it.message ?: "invalid file/password"}" })
                Toast.makeText(context, status, Toast.LENGTH_LONG).show()
            }
        }
    }

    MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFF63E6FF), secondary = Color(0xFFB38CFF), background = Color(0xFF05070C), surface = Color(0xFF0B1019))) {
        Box(Modifier.fillMaxSize().background(Brush.verticalGradient(listOf(Color(0xFF05070C), Color(0xFF081522))))) {
            when (tab) {
                0 -> HomeScreen(onOpen = { picker.launch(arrayOf("*/*")) }, busy = busy, onCrypto = { tab = 1 })
                1 -> EncryptScreen(
                    input = cryptoInput, mode = cryptoMode, password = password, status = status,
                    onPick = { cryptoPicker.launch(arrayOf("*/*")) },
                    onMode = { cryptoMode = it; status = "" },
                    onPassword = { password = it },
                    onRun = { savePicker.launch(if (cryptoMode == "encrypt") "encrypted.cdm" else "decrypted.bin") },
                    showPassword = showPassword, onShowPassword = { showPassword = !showPassword }
                )
                2 -> AnalyzeScreen(report, onOpen = { picker.launch(arrayOf("*/*")) }, onCopy = { clipboard.setText(AnnotatedString(it)) })
                3 -> SettingsScreen()
            }
            NavigationBar(modifier = Modifier.align(Alignment.BottomCenter), containerColor = Color(0xEE070B12)) {
                val items = listOf("Home" to Icons.Default.Folder, "Crypto" to Icons.Default.Lock, "Analyze" to Icons.Default.Analytics, "Settings" to Icons.Default.Settings)
                items.forEachIndexed { i, pair -> NavigationBarItem(selected = tab == i, onClick = { tab = i }, icon = { Icon(pair.second, null) }, label = { Text(pair.first) }) }
            }
        }
    }
}

@Composable private fun HomeScreen(onOpen: () -> Unit, busy: Boolean, onCrypto: () -> Unit) {
    val transition = rememberInfiniteTransition(label = "pulse")
    val scale by transition.animateFloat(0.96f, 1.04f, infiniteRepeatable(tween(1600), RepeatMode.Reverse), label = "scale")
    Column(Modifier.fillMaxSize().padding(22.dp).padding(bottom = 90.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Spacer(Modifier.height(36.dp)); Text("CD MANAGER", style = MaterialTheme.typography.headlineLarge, fontWeight = FontWeight.Black, color = Color(0xFF63E6FF))
        Text("Universal File Intelligence", color = Color.White.copy(alpha=.7f)); Spacer(Modifier.height(42.dp))
        Box(Modifier.size(190.dp).scale(scale).background(Brush.radialGradient(listOf(Color(0xFF174B70), Color.Transparent)), RoundedCornerShape(100.dp)), Alignment.Center) {
            Button(onClick = onOpen, enabled = !busy, shape = RoundedCornerShape(24.dp)) { Text(if (busy) "ANALYZING…" else "OPEN FILE") }
        }
        Spacer(Modifier.height(30.dp)); OutlinedButton(onClick = onCrypto) { Icon(Icons.Default.Lock, null); Spacer(Modifier.width(8.dp)); Text("Encrypt / Decrypt") }
        Spacer(Modifier.height(28.dp)); Text("Detect • inspect • decrypt • encrypt • verify", color = Color.White)
        Text("VPN configs • archives • documents • binaries • certificates • packages", color = Color.White.copy(alpha=.55f), modifier = Modifier.padding(top=8.dp))
    }
}

@Composable private fun AnalyzeScreen(report: FileReport?, onOpen: () -> Unit, onCopy: (String) -> Unit) {
    var rawOpen by remember { mutableStateOf(false) }
    var stringsOpen by remember { mutableStateOf(false) }
    var hexOpen by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(18.dp).padding(bottom = 90.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("ANALYZE", style = MaterialTheme.typography.headlineMedium, color = Color(0xFF63E6FF), fontWeight = FontWeight.Bold)
            OutlinedButton(onClick = onOpen) { Text("Open") }
        }
        if (report == null) { Spacer(Modifier.height(40.dp)); Text("No file analyzed yet.", color = Color.White.copy(alpha=.65f)) }
        else LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp), contentPadding = PaddingValues(vertical = 14.dp)) {
            item {
                Card(shape = RoundedCornerShape(22.dp)) { Column(Modifier.padding(18.dp)) {
                    Text(report.name, fontWeight = FontWeight.Bold); Text(report.application, color = Color(0xFF63E6FF), style = MaterialTheme.typography.titleLarge); Text(report.format, color = Color.White.copy(alpha=.78f));
                    Text("Confidence ${report.confidence}% • ${report.adapterStatus}", color = Color.White.copy(alpha=.65f), modifier = Modifier.padding(top = 4.dp))
                    if (report.protocols.isNotEmpty()) Text("Protocols: ${report.protocols.joinToString(" • ")}", color = Color.White.copy(alpha=.72f), modifier = Modifier.padding(top = 6.dp))
                    if (report.encrypted) Text("Possible encryption/compression signal detected", color = Color(0xFFFFD166), modifier = Modifier.padding(top = 6.dp))
                } }
            }
            items(report.fields) { (k,v) -> FieldRow(k,v) }
            item { Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = { stringsOpen = !stringsOpen }) { Text("Strings") }
                OutlinedButton(onClick = { hexOpen = !hexOpen }) { Text("Hex") }
                if (report.rawText != null) Button(onClick = { rawOpen = true }) { Text("Raw Format") }
            } }
            if (stringsOpen) item { PreviewCard("Strings preview", report.stringsPreview.joinToString("\n"), onCopy) }
            if (hexOpen) item { PreviewCard("Hex preview", report.hexPreview, onCopy, mono = true) }
            item { FieldRow("SHA-256", report.sha256) }
            if (report.rawText != null) item { Text("Human-readable details are shown above. Raw Format exposes the complete structured decrypted representation, including recovered credentials and configuration messages.", color = Color.White.copy(alpha=.55f)) }
            items(report.notes) { Text("• $it", color = Color.White.copy(alpha=.55f)) }
            items(report.warnings) { Text("⚠ $it", color = Color(0xFFFFC857)) }
        }
    }
    if (rawOpen && report?.rawText != null) AlertDialog(
        onDismissRequest = { rawOpen = false }, title = { Text("Raw Format") },
        text = { Box(Modifier.heightIn(max = 520.dp).verticalScroll(rememberScrollState())) { Text(report.rawText, fontFamily = FontFamily.Monospace, color = Color.White.copy(alpha=.9f)) } },
        confirmButton = { Button(onClick = { onCopy(report.rawText); rawOpen = false }) { Text("Copy Raw") } },
        dismissButton = { TextButton(onClick = { rawOpen = false }) { Text("Close") } }
    )
}

@Composable private fun FieldRow(k: String, v: String) { Row(Modifier.fillMaxWidth().background(Color.White.copy(alpha=.035f), RoundedCornerShape(12.dp)).padding(14.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) { Text(k, color = Color.White.copy(alpha=.62f), modifier = Modifier.weight(.36f)); Text(v, color = Color.White, modifier = Modifier.weight(.64f)) } }

@Composable private fun PreviewCard(title: String, text: String, onCopy: (String) -> Unit, mono: Boolean = false) { Card { Column(Modifier.padding(14.dp)) { Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { Text(title, fontWeight = FontWeight.Bold); TextButton(onClick = { onCopy(text) }) { Text("Copy") } }; Box(Modifier.heightIn(max=280.dp).verticalScroll(rememberScrollState())) { Text(text.ifBlank { "No strings detected." }, fontFamily = if (mono) FontFamily.Monospace else FontFamily.Default, color = Color.White.copy(alpha=.8f)) } } } }

@Composable private fun EncryptScreen(input: Uri?, mode: String?, password: String, status: String, onPick: () -> Unit, onMode: (String) -> Unit, onPassword: (String) -> Unit, onRun: () -> Unit, showPassword: Boolean, onShowPassword: () -> Unit) {
    Column(Modifier.fillMaxSize().padding(22.dp).padding(bottom = 90.dp)) {
        Text("CRYPTO", style = MaterialTheme.typography.headlineMedium, color = Color(0xFF63E6FF), fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(12.dp)); Text("CDM2 — authenticated local file encryption", style = MaterialTheme.typography.titleLarge)
        Text("AES-256-GCM • PBKDF2-HMAC-SHA256 • random salt/IV • streaming I/O", color = Color.White.copy(alpha=.62f), modifier = Modifier.padding(top=6.dp))
        Spacer(Modifier.height(20.dp)); OutlinedButton(onClick = onPick) { Text(if (input == null) "Select file" else (DocumentFile.fromSingleUri(LocalContext.current, input)?.name ?: "Selected file")) }
        Spacer(Modifier.height(12.dp)); Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { FilterChip(selected = mode == "encrypt", onClick = { onMode("encrypt") }, label = { Text("Encrypt") }); FilterChip(selected = mode == "decrypt", onClick = { onMode("decrypt") }, label = { Text("Decrypt") }) }
        Spacer(Modifier.height(12.dp)); OutlinedTextField(value = password, onValueChange = onPassword, label = { Text("Password") }, singleLine = true, visualTransformation = if (showPassword) androidx.compose.ui.text.input.VisualTransformation.None else androidx.compose.ui.text.input.PasswordVisualTransformation(), trailingIcon = { TextButton(onClick = onShowPassword) { Text(if (showPassword) "Hide" else "Show") } }, modifier = Modifier.fillMaxWidth())
        Spacer(Modifier.height(12.dp)); Button(onClick = onRun, enabled = input != null && mode != null && password.length >= 8) { Text("Choose output & run") }
        if (status.isNotBlank()) Text(status, color = if (status.startsWith("Failed")) Color(0xFFFF7B7B) else Color(0xFF63E6FF), modifier = Modifier.padding(top=14.dp))
        Spacer(Modifier.height(22.dp)); Card { Column(Modifier.padding(16.dp)) { Text("Security", fontWeight = FontWeight.Bold); Text("Passwords are used only for the operation and cleared from the working character array. CDM2 is intended for files you own or are authorized to process.", color = Color.White.copy(alpha=.65f), modifier = Modifier.padding(top=8.dp)) } }
    }
}

@Composable private fun SettingsScreen() {
    Column(Modifier.fillMaxSize().padding(22.dp).padding(bottom = 90.dp)) {
        Text("SETTINGS", style = MaterialTheme.typography.headlineMedium, color = Color(0xFF63E6FF), fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(18.dp))
        listOf(
            "Electro animations" to "Enabled", "Dark / AMOLED appearance" to "Enabled", "Show complete decrypted configuration" to "Enabled",
            "Persist file permissions" to "Enabled", "Offline-first analysis" to "Enabled", "Security & biometrics" to "Available for vault/key features",
            "Universal ABI build" to "armeabi-v7a • arm64-v8a • x86 • x86_64", "Open-source licenses" to "Included in project",
            "Application detection" to "Extension + content signatures + protocol fingerprints", "Protocol support" to "Protocol-agnostic analysis; V2Ray/Xray are not required", "About CD Manager" to "0.5.1 — intelligent format + protocol engine"
        ).forEach { (a,b) -> Row(Modifier.fillMaxWidth().padding(vertical = 12.dp), horizontalArrangement = Arrangement.SpaceBetween) { Text(a); Text(b, color = Color(0xFF63E6FF)) } }
    }
}
