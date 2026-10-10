package com.samvaad.android

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.samvaad.android.enroll.RecipientDeviceRecord
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadShapes
import com.samvaad.android.ui.theme.SamvaadSpacing

/**
 * Slice 11 conversation/history presentation. Stateless renderers only:
 * rows in, callbacks out. Loading, syncing, errors, and all messaging
 * dependencies live in [HomeScreen]; unsealed [MessageRow.text] arrives
 * already in memory and is never written anywhere from here.
 */

/** Fixed safe strings for the messaging surface. */
private const val CONVERSATIONS_TITLE = "Conversations"
private const val CONVERSATIONS_EMPTY = "No conversations yet."
private const val CONVERSATIONS_LOADING = "Loading conversations…"
private const val MESSAGES_EMPTY = "No messages yet."
private const val MESSAGES_LOADING = "Loading messages…"
private const val SYNC_LABEL = "Sync"
private const val SYNCING_LABEL = "Syncing…"
private const val BACK_LABEL = "Back"
private const val NEW_MESSAGE_LABEL = "New message"
private const val USERNAME_LABEL = "Friend username"
private const val FIND_DEVICES_LABEL = "Find devices"
private const val FINDING_DEVICES_LABEL = "Finding devices…"
private const val NO_DEVICES_LABEL = "No active devices for this user."
private const val MESSAGE_LABEL = "Message"
private const val SEND_LABEL = "Send"
private const val SENDING_LABEL_BUTTON = "Sending…"
private const val RETRY_LABEL = "Retry"

@Composable
fun ConversationListUi(
    conversations: List<ConversationRow>?,
    loadError: String?,
    onRetryLoad: () -> Unit,
    syncing: Boolean,
    syncError: String?,
    onSync: () -> Unit,
    onSelect: (String) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = CONVERSATIONS_TITLE,
                style = MaterialTheme.typography.titleMedium
            )
            Button(onClick = onSync, enabled = !syncing) {
                Text(if (syncing) SYNCING_LABEL else SYNC_LABEL)
            }
        }
        syncError?.let { error ->
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error
            )
        }
        // Plain val for smart casts (`by`-delegated state never smart-casts).
        val rows = conversations
        val failure = loadError
        if (rows == null) {
            if (failure == null) {
                Text(
                    text = CONVERSATIONS_LOADING,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Text(
                    text = failure,
                    color = MaterialTheme.colorScheme.error
                )
                TextButton(onClick = onRetryLoad) {
                    Text(RETRY_LABEL)
                }
            }
        } else if (rows.isEmpty()) {
            Text(
                text = CONVERSATIONS_EMPTY,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            rows.forEach { row ->
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onSelect(row.conversationId) }
                        .padding(vertical = 4.dp),
                ) {
                    Text(
                        text = row.peerLabel +
                            if (row.hasPending) " •" else "",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = row.previewText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                    )
                }
            }
        }
    }
}

@Composable
fun ConversationDetailUi(
    peerLabel: String,
    messages: List<MessageRow>?,
    loadError: String?,
    onRetryLoad: () -> Unit,
    syncing: Boolean,
    syncError: String?,
    onBack: () -> Unit,
    onSync: () -> Unit,
    composer: @Composable () -> Unit,
    /**
     * Slice B: the shell top bar owns back in external navigation, so
     * the Detail destination hides this row-level button. Full (legacy)
     * mode keeps it.
     */
    showBack: Boolean = true,
) {
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            if (showBack) {
                TextButton(onClick = onBack) {
                    Text(BACK_LABEL)
                }
            }
            Text(
                text = peerLabel,
                style = MaterialTheme.typography.titleMedium
            )
            Button(onClick = onSync, enabled = !syncing) {
                Text(if (syncing) SYNCING_LABEL else SYNC_LABEL)
            }
        }
        syncError?.let { error ->
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error
            )
        }
        // Plain val for smart casts (`by`-delegated state never smart-casts).
        val items = messages
        val failure = loadError
        if (items == null) {
            if (failure == null) {
                Text(
                    text = MESSAGES_LOADING,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Text(
                    text = failure,
                    color = MaterialTheme.colorScheme.error
                )
                TextButton(onClick = onRetryLoad) {
                    Text(RETRY_LABEL)
                }
            }
        } else if (items.isEmpty()) {
            Text(
                text = MESSAGES_EMPTY,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            // Plain Column, not lazy: this screen already lives inside
            // the root verticalScroll, where unbounded lazy lists break.
            // Reads are bounded by MESSAGE_PAGE_LIMIT at the loader.
            items.forEach {
                Column(modifier = Modifier.fillMaxWidth()) {
                    Text(
                        text = it.senderLabel,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = it.text,
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Text(
                        text = it.meta,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
        Text(
            text = NEW_MESSAGE_LABEL,
            style = MaterialTheme.typography.titleSmall
        )
        composer()
    }
}

@Composable
fun ComposerUi(
    username: String,
    onUsernameChange: (String) -> Unit,
    draft: String,
    onDraftChange: (String) -> Unit,
    devices: List<RecipientDeviceRecord>?,
    findingDevices: Boolean,
    directoryError: String?,
    selectedDeviceId: String?,
    onFindDevices: () -> Unit,
    onSelectDevice: (String) -> Unit,
    sending: Boolean,
    sendError: String?,
    onSend: () -> Unit,
) {
    // Slice E visual redesign: same elements, same order, same strings,
    // same guards. Fields go full width, spacing uses design tokens, and
    // the draft + send pair sits in a tonal card that reads as one
    // message field. The IME send action mirrors the Send button guard.
    val canSend = selectedDeviceId != null && draft.isNotBlank() && !sending
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
    ) {
        OutlinedTextField(
            value = username,
            onValueChange = onUsernameChange,
            label = { Text(USERNAME_LABEL) },
            singleLine = true,
            enabled = !sending && !findingDevices,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = onFindDevices,
            enabled = username.isNotBlank() && !sending && !findingDevices,
            modifier = Modifier.heightIn(min = SamvaadDimens.MinTouchTarget),
        ) {
            Text(if (findingDevices) FINDING_DEVICES_LABEL else FIND_DEVICES_LABEL)
        }
        directoryError?.let { error ->
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error
            )
        }
        val found = devices
        if (found != null) {
            if (found.isEmpty()) {
                Text(
                    text = NO_DEVICES_LABEL,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                // Explicit selection only: nothing is preselected, and the
                // caller must pick exactly one device before sending.
                found.forEach { device ->
                    val selected = device.deviceId == selectedDeviceId
                    Button(
                        onClick = { onSelectDevice(device.deviceId) },
                        enabled = !sending,
                        modifier = Modifier.heightIn(min = SamvaadDimens.MinTouchTarget),
                    ) {
                        Text(
                            (if (selected) "✓ " else "") +
                                "${device.deviceRole} · #${device.signalDeviceId}"
                        )
                    }
                }
            }
        }
        Surface(
            shape = SamvaadShapes.medium,
            color = MaterialTheme.colorScheme.surfaceContainerLow,
            contentColor = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
                modifier = Modifier.padding(SamvaadSpacing.Medium),
            ) {
                OutlinedTextField(
                    value = draft,
                    onValueChange = onDraftChange,
                    label = { Text(MESSAGE_LABEL) },
                    enabled = !sending,
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Send),
                    keyboardActions = KeyboardActions(
                        onSend = { if (canSend) onSend() },
                    ),
                    modifier = Modifier.fillMaxWidth(),
                )
                Button(
                    onClick = onSend,
                    enabled = canSend,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = SamvaadDimens.MinTouchTarget),
                ) {
                    Text(if (sending) SENDING_LABEL_BUTTON else SEND_LABEL)
                }
            }
        }
        sendError?.let { error ->
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error
            )
        }
    }
}
