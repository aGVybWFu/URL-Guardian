package org.urlguardian.app

import android.content.ComponentName
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.urlguardian.app.core.Action
import org.urlguardian.app.core.AnalysisResult
import org.urlguardian.app.core.AnalyzerFactory
import org.urlguardian.app.core.BundleSource
import org.urlguardian.app.core.BundleStatus
import org.urlguardian.app.core.IntentLoopGuard
import org.urlguardian.app.core.SecurityAnalyzer
import org.urlguardian.app.core.TiBundleStore
import org.urlguardian.app.core.UnsupportedSchemeException

class MainActivity : ComponentActivity() {
    private var analyzer: SecurityAnalyzer? = null
    private var bundleStatus: BundleStatus = BundleStatus.NONE
    private var loadFailure: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val created = runCatching { createAnalyzer() }
        analyzer = created.getOrNull()
        loadFailure = created.exceptionOrNull()?.let {
            "UNAVAILABLE：模型或資產無法載入，已停止分析（${it.message ?: "asset error"}）"
        }
        val incoming = intent.takeIf { it.action == Intent.ACTION_VIEW }?.dataString.orEmpty()
        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFFF7FAF8)) {
                    GuardianScreen(
                        incoming, analyzer, bundleStatus, loadFailure,
                        ::openInExternalBrowser, ::openDefaultAppsSettings, ::rollbackThreatIntel,
                    )
                }
            }
        }
    }

    override fun onDestroy() {
        analyzer?.close()
        super.onDestroy()
    }

    private fun createAnalyzer(): SecurityAnalyzer {
        val (created, status) = AnalyzerFactory.create(this)
        bundleStatus = status
        return created
    }

    private fun openDefaultAppsSettings() {
        val intent = Intent(android.provider.Settings.ACTION_MANAGE_DEFAULT_APPS_SETTINGS)
        try {
            startActivity(intent)
        } catch (_: Exception) {
            startActivity(
                Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName"))
            )
        }
    }

    private fun rollbackThreatIntel() {
        val status = TiBundleStore(this).rollbackToPrevious()
        bundleStatus = status
        android.widget.Toast.makeText(
            this,
            if (status.snapshotId != null) "情資包已回復：${status.snapshotId}" else "沒有可回復的上一版情資",
            android.widget.Toast.LENGTH_SHORT,
        ).show()
        recreate()
    }

    private fun openInExternalBrowser(url: String) {
        val base = Intent(Intent.ACTION_VIEW, Uri.parse(url)).addCategory(Intent.CATEGORY_BROWSABLE)
        val resolved = packageManager.queryIntentActivities(base, 0)
        val allowedPackages = IntentLoopGuard.externalPackages(packageName, resolved.map { it.activityInfo.packageName })
        val targets = resolved
            .filter { it.activityInfo.packageName in allowedPackages }
            .map { info -> Intent(base).apply { component = ComponentName(info.activityInfo.packageName, info.activityInfo.name) } }
        if (targets.isEmpty()) return
        if (targets.size == 1) {
            startActivity(targets.first())
            return
        }
        val chooser = Intent.createChooser(targets.first(), "選擇外部瀏覽器")
        chooser.putExtra(Intent.EXTRA_INITIAL_INTENTS, targets.drop(1).toTypedArray())
        startActivity(chooser)
    }
}

@Composable
private fun GuardianScreen(
    incoming: String,
    analyzer: SecurityAnalyzer?,
    bundleStatus: BundleStatus,
    loadFailure: String?,
    openExternal: (String) -> Unit,
    openSettings: () -> Unit,
    rollback: () -> Unit,
) {
    var input by rememberSaveable { mutableStateOf(incoming) }
    var lastAnalyzedInput by rememberSaveable { mutableStateOf(incoming) }
    var result by remember { mutableStateOf<AnalysisResult?>(null) }
    var error by remember { mutableStateOf<String?>(loadFailure) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun analyze(value: String = input) {
        val active = analyzer ?: return
        lastAnalyzedInput = value
        busy = true
        error = null
        result = null
        scope.launch {
            try {
                result = withContext(Dispatchers.Default) { active.analyze(value) }
            } catch (exception: UnsupportedSchemeException) {
                error = "UNSUPPORTED_SCHEME：只支援 http 與 https 網址，其他類型不會被分析或開啟。"
            } catch (exception: Exception) {
                error = exception.message ?: "無法分析此網址"
            } finally {
                busy = false
            }
        }
    }

    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        Text("URL Guardian", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, color = Color(0xFF087F5B))
        Text("在裝置上分析網址。結果是風險提示，不是安全保證。")
        OutlinedTextField(
            value = input,
            onValueChange = { input = it },
            label = { Text("網址") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Button(
            onClick = ::analyze,
            enabled = analyzer != null && input.isNotBlank() && !busy,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Text(if (busy) "分析中…" else "分析網址")
        }
        error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        result?.let { analysis ->
            ResultCard(analysis)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(onClick = { result = null }, modifier = Modifier.weight(1f)) { Text("取消") }
                if (analysis.decision.action != Action.BLOCK) {
                    Button(onClick = { openExternal(analysis.normalizedUrl) }, modifier = Modifier.weight(1f)) {
                        Text(if (analysis.decision.action == Action.REVIEW) "了解風險並繼續" else "使用外部瀏覽器開啟")
                    }
                }
            }
        }
        Spacer(Modifier.height(12.dp))
        Text(bundleStatusLine(bundleStatus), style = MaterialTheme.typography.bodySmall)
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            OutlinedButton(onClick = openSettings, modifier = Modifier.weight(1f)) { Text("系統預設應用程式設定") }
            if (bundleStatus.hasPrevious) {
                OutlinedButton(onClick = rollback, modifier = Modifier.weight(1f)) { Text("回復上一版情資") }
            }
        }
        Text(
            "URL Guardian 是安全攔截器，不是瀏覽器替代品；Android 的瀏覽器角色需要完整瀏覽功能，本 App 不申請。",
            style = MaterialTheme.typography.bodySmall,
        )
        Text("離線模型與凍結威脅情資；不會連線抓取目標網址。", style = MaterialTheme.typography.bodySmall)
    }

    LaunchedEffect(Unit) {
        if (lastAnalyzedInput.isNotBlank()) analyze(lastAnalyzedInput)
    }
}

internal fun bundleStatusLine(status: BundleStatus): String {
    if (status.bundleVersion == null) {
        return "情資包：未載入（${status.lastError ?: "無"}）"
    }
    val source = when (status.source) {
        BundleSource.ASSET -> "內建"
        BundleSource.IMPORTED -> "已匯入"
        BundleSource.ROLLED_BACK -> "已回復"
        BundleSource.NONE -> "無"
    }
    val error = status.lastError?.let { "；$it" }.orEmpty()
    val age = if (status.ageDays != null) "，${status.ageDays} 天前，${status.staleness.name}" else ""
    val previous = status.previousSnapshotId?.let { "；上一版 $it" }.orEmpty()
    return "情資包：${status.bundleVersion}（$source，完整性 OK，" +
        "${status.indicatorCount} 指標 / ${status.brandCount} 品牌 / ${status.shortenerCount} 短網址，" +
        "${status.snapshotId ?: "未知快照"}$age$previous）$error"
}

@Composable
private fun ResultCard(result: AnalysisResult) {
    val actionColor = when (result.decision.action) {
        Action.ALLOW -> Color(0xFF087F5B)
        Action.REVIEW -> Color(0xFF9A6700)
        Action.BLOCK -> Color(0xFFB42318)
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Text(result.decision.action.name, fontWeight = FontWeight.Bold, color = actionColor, style = MaterialTheme.typography.titleLarge)
            Text("正規化網址：${redactQuery(result.normalizedUrl)}")
            Text("威脅情資：${result.threatIntelStatus.name}")
            Text("釣魚機率：${"%.4f".format(result.phishingProbability)}（未校準機率）")
            Text("風險：${result.decision.risk.name}")
            Text("原因代碼：${result.decision.reasonCode.code}")
            Text("原因：${result.decision.reasonCode.message}")
            Text("品牌比對：${brandLine(result)}")
            Text("短網址：${if (result.shortener.detected) "是（${result.shortener.domain}）" else "否"}")
            Text("重新導向：${redirectLine(result)}")
            Text("風險訊號數：${result.decision.evidenceCount}")
            Text("政策：${result.decision.engineVersion}（0.35 / 0.85）")
            Text("模型：${result.modelVersion}")
            Text("快照：${result.snapshotVersion}")
        }
    }
}

private fun brandLine(result: AnalysisResult): String {
    val brand = result.brand
    if (!brand.detected) return "未偵測到品牌名稱"
    val ids = brand.brands.joinToString(",") { it.brandId }
    return when {
        brand.officialDomain -> "品牌官方網域（$ids）"
        brand.domainMismatch -> "網域不符（$ids，分數 ${"%.2f".format(brand.riskScore)}）"
        else -> "僅路徑提及（$ids）"
    }
}

private fun redirectLine(result: AnalysisResult): String {
    val redirect = result.redirect
    if (!redirect.observed) return "未觀察（靜態分析不展開網址）"
    return "已觀察（${redirect.redirectCount} 次，跨網域：${if (redirect.crossDomainRedirect) "是" else "否"}）"
}

internal fun redactQuery(url: String): String {
    val withoutCredentials = url.replace(Regex("^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@")) { match ->
        match.groupValues[1] + "REDACTED@"
    }
    val beforeFragment = withoutCredentials.substringBefore('#')
    val fragment = if ('#' in withoutCredentials) "#REDACTED" else ""
    return if ('?' in beforeFragment) beforeFragment.substringBefore('?') + "?REDACTED" + fragment else beforeFragment + fragment
}
