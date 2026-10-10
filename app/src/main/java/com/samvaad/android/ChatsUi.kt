package com.samvaad.android

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import com.samvaad.android.ui.ds.EmptyState
import com.samvaad.android.ui.ds.SamvaadTextField
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadShapes
import com.samvaad.android.ui.theme.SamvaadSpacing
import com.samvaad.android.ui.util.formatServerTimestamp

/**
 * Slice C Chats list rehaul: the primary product surface.
 *
 * Stateless renderers only (rows in, callbacks out), mirroring the
 * [ConversationListUi] contract so the legacy Full-mode rendering keeps
 * working untouched. Loading, syncing, errors, and all messaging
 * dependencies live in [HomeScreen]; unsealed preview text arrives
 * already in memory and is never written anywhere from here.
 *
 * What the existing model supports per row — and nothing more:
 * - identity: [ConversationRow.peerLabel] (username, else conversation ID);
 * - preview: latest unsealed text, or the fixed fail-closed placeholder
 *   when sealed content cannot be opened (rendered as-is, never raw bytes);
 * - attention: [ConversationRow.hasPending] only (outbound rows not yet
 *   server-accepted) — rendered as the text "Sending…", never a color-
 *   alone or symbol-alone marker. No unread counts exist anywhere in the
 *   model, so none are shown; no delivery states beyond pending exist, so
 *   no "read"/"delivered" indicators are fabricated;
 * - time: the latest row's raw server timestamp via
 *   [formatServerTimestamp] (safe fallback behavior preserved).
 * No avatars exist server-side: rows use a deterministic initials avatar
 * (stable slot + letters derived from the label, no image loading).
 */

/** List header + sync strings, shared with the legacy list language. */
private const val CHATS_TITLE = "Conversations"
private const val CHATS_EMPTY_TITLE = "No conversations yet."
private const val CHATS_EMPTY_DESCRIPTION = "Your conversations will appear here."
private const val CHATS_NO_MATCH_TITLE = "No matching conversations."
private const val CHATS_NO_MATCH_DESCRIPTION = "Try a different search."
private const val SEARCH_LABEL = "Search conversations"
private const val CLEAR_LABEL = "Clear"
private const val SYNC_LABEL = "Sync"
private const val SYNCING_LABEL = "Syncing…"
private const val RETRY_LABEL = "Retry"
private const val SENT_FALLBACK_LABEL = "Sent"
private const val OUTBOUND_PREFIX = "You: "

/** Deterministic initials for the generated avatar. Never blank. */
fun conversationInitials(label: String): String {
    val parts = label.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
    if (parts.isEmpty()) return "?"
    val first = parts.first().first().uppercaseChar()
    if (parts.size == 1) return first.toString()
    return "$first${parts[1].first().uppercaseChar()}"
}

/**
 * Deterministic avatar palette slot for a label. Pure function of the
 * string (Kotlin `hashCode` is specified stable), so the color never
 * shifts across recompositions; the composable maps the slot onto
 * Material 3 container roles (no raw colors at call sites).
 */
fun avatarSlot(label: String): Int =
    (label.hashCode() and Int.MAX_VALUE) % AVATAR_SLOTS

private const val AVATAR_SLOTS = 3

/**
 * Deterministic initials avatar (Slice C). Shared with the Friends
 * destination so both lists speak the same visual identity: callers
 * pass a display label, never an image or URL.
 */
@Composable
internal fun ConversationAvatar(label: String) {
    val scheme = MaterialTheme.colorScheme
    val (container, content) = when (avatarSlot(label)) {
        0 -> scheme.primaryContainer to scheme.onPrimaryContainer
        1 -> scheme.secondaryContainer to scheme.onSecondaryContainer
        else -> scheme.tertiaryContainer to scheme.onTertiaryContainer
    }
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(SamvaadDimens.MinTouchTarget)
            .clip(CircleShape)
            .background(container)
            // Decorative: the row description already names the peer, so
            // the initials must not announce redundantly.
            .clearAndSetSemantics {},
    ) {
        Text(
            text = conversationInitials(label),
            style = MaterialTheme.typography.titleMedium,
            color = content,
        )
    }
}

@Composable
private fun ConversationRowUi(
    row: ConversationRow,
    onSelect: (String) -> Unit,
) {
    val preview = if (row.previewIsOutbound) {
        OUTBOUND_PREFIX + row.previewText
    } else {
        row.previewText
    }
    // SENDING_LABEL is the shared outbound-pending marker (same package).
    val time = if (row.hasPending) {
        SENDING_LABEL
    } else {
        formatServerTimestamp(row.previewTimestamp).ifEmpty { SENT_FALLBACK_LABEL }
    }
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            // Inline lambda, not a bound reference (see Slice B finding).
            .clickable(role = Role.Button) { onSelect(row.conversationId) }
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.Medium,
            )
            // One announcement per row: peer, preview, time. Merged so
            // text queries still resolve to this clickable node.
            .semantics(mergeDescendants = true) {
                contentDescription = "${row.peerLabel}, $preview, $time"
            },
    ) {
        ConversationAvatar(label = row.peerLabel)
        Spacer(modifier = Modifier.width(SamvaadSpacing.Medium))
        Column(modifier = Modifier.weight(1f)) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    text = row.peerLabel,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Spacer(modifier = Modifier.width(SamvaadSpacing.Small))
                Text(
                    text = time,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Spacer(modifier = Modifier.height(SamvaadSpacing.XSmall))
            Text(
                text = preview,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** Compact loading treatment: static skeleton rows, no spinner wall. */
@Composable
private fun ChatsSkeletonRow() {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.Medium,
            ),
    ) {
        Box(
            modifier = Modifier
                .size(SamvaadDimens.MinTouchTarget)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.surfaceVariant),
        )
        Spacer(modifier = Modifier.width(SamvaadSpacing.Medium))
        Column(
            verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.XSmall),
            modifier = Modifier.weight(1f),
        ) {
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction = 0.45f)
                    .height(SamvaadSpacing.Large)
                    .clip(SamvaadShapes.small)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            )
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction = 0.8f)
                    .height(SamvaadSpacing.Medium)
                    .clip(SamvaadShapes.small)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            )
        }
    }
}

/**
 * Local conversation filter (Slice G). Pure in-memory match over the
 * already-loaded rows — peer, preview, and conversation ID — so search
 * never touches the network, the database, or crypto. Blank queries
 * return the list unchanged.
 */
fun filterConversations(
    rows: List<ConversationRow>,
    query: String,
): List<ConversationRow> {
    val trimmed = query.trim()
    if (trimmed.isEmpty()) return rows
    return rows.filter { row ->
        row.peerLabel.contains(trimmed, ignoreCase = true) ||
            row.previewText.contains(trimmed, ignoreCase = true) ||
            row.conversationId.contains(trimmed, ignoreCase = true)
    }
}

private const val SKELETON_ROWS = 4

@Composable
fun ChatsScreen(
    conversations: List<ConversationRow>?,
    loadError: String?,
    onRetryLoad: () -> Unit,
    syncing: Boolean,
    syncError: String?,
    onSync: () -> Unit,
    onSelect: (String) -> Unit,
    /**
     * Existing new-message flow, preserved as the trailing item so the
     * scroll-to-composer behavior is unchanged.
     */
    composer: @Composable () -> Unit,
) {
    // Plain val for smart casts (`by`-delegated state never smart-casts).
    val rows = conversations
    val failure = loadError
    // Slice G local search: UI state owned here (per-destination mount,
    // rotation-safe). Filters the already-loaded rows only — no network,
    // no storage, no crypto on any keystroke.
    var query by rememberSaveable { mutableStateOf("") }
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .testTag("ChatsList"),
    ) {
        item(key = "header") {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(
                        horizontal = SamvaadSpacing.Large,
                        vertical = SamvaadSpacing.Small,
                    ),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = CHATS_TITLE,
                    style = MaterialTheme.typography.titleMedium,
                )
                Button(
                    onClick = onSync,
                    enabled = !syncing,
                    modifier = Modifier.heightIn(min = SamvaadDimens.MinTouchTarget),
                ) {
                    Text(if (syncing) SYNCING_LABEL else SYNC_LABEL)
                }
            }
        }
        syncError?.let { error ->
            item(key = "sync-error") {
                StatusCard(
                    kind = StatusKind.Warning,
                    message = error,
                    modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
                )
            }
        }
        if (rows == null) {
            if (failure == null) {
                item(key = "loading") {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .testTag("ChatsLoading")
                            .semantics {
                                contentDescription = "Loading conversations"
                            },
                    ) {
                        repeat(SKELETON_ROWS) { ChatsSkeletonRow() }
                    }
                }
            } else {
                item(key = "load-error") {
                    StatusCard(
                        kind = StatusKind.Error,
                        message = failure,
                        actionLabel = RETRY_LABEL,
                        // Inline lambda, not a bound reference.
                        onAction = { onRetryLoad() },
                        modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
                    )
                }
            }
        } else if (rows.isEmpty()) {
            item(key = "empty") {
                EmptyState(
                    title = CHATS_EMPTY_TITLE,
                    description = CHATS_EMPTY_DESCRIPTION,
                )
            }
        } else {
            item(key = "search") {
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = SamvaadSpacing.Large),
                ) {
                    SamvaadTextField(
                        value = query,
                        // Inline lambda, not a bound reference.
                        onValueChange = { query = it },
                        label = SEARCH_LABEL,
                        modifier = Modifier.weight(1f),
                    )
                    if (query.isNotEmpty()) {
                        TextButton(
                            onClick = { query = "" },
                            modifier = Modifier.heightIn(
                                min = SamvaadDimens.MinTouchTarget,
                            ),
                        ) {
                            Text(CLEAR_LABEL)
                        }
                    }
                }
            }
            val visible = filterConversations(rows, query)
            if (visible.isEmpty()) {
                item(key = "no-match") {
                    EmptyState(
                        title = CHATS_NO_MATCH_TITLE,
                        description = CHATS_NO_MATCH_DESCRIPTION,
                    )
                }
            } else {
                items(
                    items = visible,
                    key = { it.conversationId },
                ) { row ->
                    ConversationRowUi(
                        row = row,
                        // Inline lambda, not a bound reference.
                        onSelect = { onSelect(it) },
                    )
                }
            }
        }
        item(key = "composer") {
            Column(
                modifier = Modifier.padding(
                    horizontal = SamvaadSpacing.Large,
                    vertical = SamvaadSpacing.Small,
                ),
            ) {
                composer()
            }
        }
    }
}
