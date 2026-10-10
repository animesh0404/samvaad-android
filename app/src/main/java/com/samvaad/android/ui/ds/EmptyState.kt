package com.samvaad.android.ui.ds

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadSpacing

/**
 * Samvaad empty state (Slice A).
 *
 * Centered icon/visual slot, title, description, optional CTA.
 * Production-ready and testable; broad adoption arrives with the
 * conversation/friends slices.
 */
@Composable
fun EmptyState(
    title: String,
    description: String,
    modifier: Modifier = Modifier,
    visual: (@Composable () -> Unit)? = null,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(
            SamvaadSpacing.Small,
            Alignment.CenterVertically,
        ),
        horizontalAlignment = Alignment.CenterHorizontally,
        modifier = modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.XLarge,
                vertical = SamvaadSpacing.Large,
            ),
    ) {
        if (visual != null) {
            visual()
        }
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            textAlign = TextAlign.Center,
        )
        Text(
            text = description,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        if (actionLabel != null && onAction != null) {
            Button(
                onClick = onAction,
                // Slice H: the CTA meets the 48dp touch target.
                modifier = Modifier.heightIn(
                    min = SamvaadDimens.MinTouchTarget,
                ),
            ) {
                Text(actionLabel)
            }
        }
    }
}
