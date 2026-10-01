package com.samvaad.android

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.samvaad.android.ui.theme.SamvaadTheme

/**
 * One-shot first-bootstrap recovery-code display.
 *
 * The codes are shown exactly once: they arrive here as transient Compose
 * state, are never persisted, never logged, and are dropped when the user
 * acknowledges (or the process dies — the server never re-issues them).
 */
@Composable
fun RecoveryCodesScreen(
    codes: List<String>,
    onAcknowledge: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Text(
            text = "Save your recovery codes",
            style = MaterialTheme.typography.headlineSmall
        )
        Text(
            text = "These 25 codes are the only way to recover your account " +
                "if this device is lost. Store them somewhere safe, " +
                "outside this app. They will never be shown again.",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        codes.forEachIndexed { index, code ->
            Text(
                text = "${index + 1}. $code",
                style = MaterialTheme.typography.bodyMedium.copy(
                    fontFamily = FontFamily.Monospace
                ),
                modifier = Modifier.fillMaxWidth()
            )
        }
        Button(onClick = onAcknowledge) {
            Text("I have saved these codes")
        }
    }
}

@Preview(showBackground = true)
@Composable
fun RecoveryCodesScreenPreview() {
    SamvaadTheme {
        RecoveryCodesScreen(
            codes = listOf("abcd-efgh-ijkl-mnop", "qrst-uvwx-yz12-3456"),
            onAcknowledge = {}
        )
    }
}
