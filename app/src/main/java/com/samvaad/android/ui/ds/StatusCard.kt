package com.samvaad.android.ui.ds

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.semantics
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadSpacing

/**
 * Samvaad status card (Slice A).
 *
 * Semantic variants mapped to Material 3 container roles; no raw colors
 * at call sites. Deliberately icon-free: `material-icons-core` is not a
 * project dependency and this slice adds none. Revisit a leading icon
 * (or a Canvas-drawn mark) in Slice B if the dep is accepted then.
 *
 * Error-kind cards expose the message through error semantics so screen
 * readers announce the failure.
 */
enum class StatusKind {
    Info,
    Warning,
    Error,
    Success,
}

@Composable
fun StatusCard(
    kind: StatusKind,
    message: String,
    modifier: Modifier = Modifier,
    title: String? = null,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    val scheme = MaterialTheme.colorScheme
    val (container, content) = when (kind) {
        StatusKind.Info -> scheme.secondaryContainer to scheme.onSecondaryContainer
        StatusKind.Warning -> scheme.tertiaryContainer to scheme.onTertiaryContainer
        StatusKind.Error -> scheme.errorContainer to scheme.onErrorContainer
        StatusKind.Success -> scheme.primaryContainer to scheme.onPrimaryContainer
    }
    Card(
        colors = CardDefaults.cardColors(
            containerColor = container,
            contentColor = content,
        ),
        modifier = modifier
            .fillMaxWidth()
            .semantics { if (kind == StatusKind.Error) error(message) },
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
            modifier = Modifier.padding(SamvaadSpacing.Large),
        ) {
            if (title != null) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                )
            }
            Text(
                text = message,
                style = MaterialTheme.typography.bodyMedium,
            )
            if (actionLabel != null && onAction != null) {
                TextButton(
                    onClick = onAction,
                    // Slice G: actions meet the 48dp touch target.
                    modifier = Modifier.heightIn(
                        min = SamvaadDimens.MinTouchTarget,
                    ),
                ) {
                    Text(actionLabel)
                }
            }
        }
    }
}
