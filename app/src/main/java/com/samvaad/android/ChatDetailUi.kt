package com.samvaad.android

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import com.samvaad.android.ui.ds.EmptyState
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadShapes
import com.samvaad.android.ui.theme.SamvaadSpacing
import com.samvaad.android.ui.util.formatServerTimestamp
import com.samvaad.android.ui.util.messageDayLabel
import kotlinx.coroutines.launch

/**
 * Slice E Chat Detail rehaul: messenger-style conversation surface.
 *
 * Stateless renderers only (rows in, callbacks out), mirroring the
 * [ConversationDetailUi] contract so the legacy Full-mode rendering
 * keeps working untouched. Loading, syncing, errors, realtime
 * reloading, and all messaging dependencies live in [HomeScreen];
 * unsealed [MessageRow.text] arrives already in memory and is never
 * written anywhere from here.
 *
 * Only actually-supported message states are represented: unaccepted
 * outbound rows show the shared "Sending…" marker; everything else
 * shows its server timestamp (or the legacy "Sent" fallback when the
 * server stamped nothing — mirroring the detail meta rule). There is
 * no per-message failed state in the model, no delivery/read metadata
 * anywhere, and no per-message retry handle (Sync recovers durable
 * rows), so no checkmarks, no failed badges, and no retry buttons are
 * invented here.
 */

/** Detail header + sync strings, shared with the legacy detail language. */
private const val DETAIL_EMPTY_TITLE = "No messages yet."
private const val DETAIL_EMPTY_DESCRIPTION =
    "Messages you send and receive will appear here."
private const val SYNC_LABEL = "Sync"
private const val SYNCING_LABEL = "Syncing…"
private const val RETRY_LABEL = "Retry"
private const val SENT_FALLBACK_LABEL = "Sent"
private const val NEW_MESSAGES_LABEL = "New messages"

/** Max bubble width as a fraction of the list width (no hardcoded dp). */
private const val BUBBLE_MAX_FRACTION = 0.85f

private const val SKELETON_BUBBLES = 4

/** Caption under the last bubble of each direction group. */
private fun bubbleCaption(row: MessageRow): String {
    if (row.hasPendingState) return SENDING_LABEL
    return formatServerTimestamp(row.serverTimestamp).ifEmpty { SENT_FALLBACK_LABEL }
}

/** True when the row is an unaccepted outbound row (the only "pending"). */
private val MessageRow.hasPendingState: Boolean
    get() = isOutbound && meta == SENDING_LABEL

@Composable
private fun MessageBubble(
    row: MessageRow,
    peerLabel: String,
    showSender: Boolean,
    showTime: Boolean,
) {
    val scheme = MaterialTheme.colorScheme
    val (container, content) = if (row.isOutbound) {
        scheme.primaryContainer to scheme.onPrimaryContainer
    } else {
        scheme.surfaceContainerHigh to scheme.onSurface
    }
    val caption = bubbleCaption(row)
    val spokenSender = row.senderLabel.ifEmpty { peerLabel }
    Box(
        contentAlignment = if (row.isOutbound) {
            Alignment.CenterEnd
        } else {
            Alignment.CenterStart
        },
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            horizontalAlignment = if (row.isOutbound) {
                Alignment.End
            } else {
                Alignment.Start
            },
            modifier = Modifier
                .fillMaxWidth(BUBBLE_MAX_FRACTION)
                // One announcement per bubble: who, what, when/state.
                // No actions live inside, so merging stays unambiguous.
                .semantics(mergeDescendants = true) {
                    contentDescription = "$spokenSender, ${row.text}, $caption"
                },
        ) {
            if (showSender) {
                Text(
                    text = row.senderLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = scheme.onSurfaceVariant,
                    maxLines = 1,
                    modifier = Modifier.testTag("MessageSenderLabel"),
                )
                Spacer(modifier = Modifier.height(SamvaadSpacing.XSmall))
            }
            Surface(
                shape = SamvaadShapes.medium,
                color = container,
                contentColor = content,
            ) {
                Text(
                    text = row.text,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.padding(
                        horizontal = SamvaadSpacing.Medium,
                        vertical = SamvaadSpacing.Small,
                    ),
                )
            }
            if (showTime) {
                Spacer(modifier = Modifier.height(SamvaadSpacing.XSmall))
                Text(
                    text = caption,
                    style = MaterialTheme.typography.labelSmall,
                    color = scheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
    }
}

@Composable
private fun DateSeparator(label: String) {
    Row(
        horizontalArrangement = Arrangement.Center,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = SamvaadSpacing.Small)
            .semantics {
                contentDescription = label
            },
    ) {
        Surface(
            shape = SamvaadShapes.small,
            color = MaterialTheme.colorScheme.surfaceVariant,
            contentColor = MaterialTheme.colorScheme.onSurfaceVariant,
        ) {
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                modifier = Modifier.padding(
                    horizontal = SamvaadSpacing.Medium,
                    vertical = SamvaadSpacing.XSmall,
                ),
            )
        }
    }
}

@Composable
private fun DetailSkeletonBubble(index: Int) {
    val outbound = index % 2 == 1
    Box(
        contentAlignment = if (outbound) {
            Alignment.CenterEnd
        } else {
            Alignment.CenterStart
        },
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = SamvaadSpacing.XSmall),
    ) {
        Column(
            verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.XSmall),
        ) {
            Box(
                modifier = Modifier
                    .width(SamvaadSpacing.XXLarge * 6)
                    .height(SamvaadSpacing.Large)
                    .clip(SamvaadShapes.small)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            )
            Box(
                modifier = Modifier
                    .width(SamvaadSpacing.XXLarge * 4)
                    .height(SamvaadSpacing.Medium)
                    .clip(SamvaadShapes.small)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            )
        }
    }
}

@Composable
fun ChatDetailScreen(
    peerLabel: String,
    messages: List<MessageRow>?,
    loadError: String?,
    onRetryLoad: () -> Unit,
    syncing: Boolean,
    syncError: String?,
    onSync: () -> Unit,
    /**
     * Existing new-message flow, preserved as the fixed footer so the
     * composer never scrolls away and the keyboard insets apply cleanly.
     */
    composer: @Composable () -> Unit,
) {
    // Plain vals for smart casts (`by`-delegated state never smart-casts).
    val rows = messages
    val failure = loadError
    val listState = rememberLazyListState()
    // Scroll bookkeeping only: counts and pill visibility derive from
    // the already-loaded list. No new collectors, no lifecycle changes.
    var lastCount by remember { mutableStateOf<Int?>(null) }
    var showPill by remember { mutableStateOf(false) }
    val followScope = rememberCoroutineScope()
    LaunchedEffect(rows?.size) {
        val size = rows?.size ?: return@LaunchedEffect
        val previous = lastCount
        lastCount = size
        if (size == 0) {
            showPill = false
            return@LaunchedEffect
        }
        if (previous == null) {
            // First load: latest messages visible immediately.
            listState.scrollToItem(size - 1)
            showPill = false
        } else if (size > previous) {
            if (!listState.canScrollForward) {
                listState.scrollToItem(size - 1)
                showPill = false
            } else {
                showPill = true
            }
        }
    }
    // The user scrolled back to the bottom by hand: the pill is stale.
    val atBottom = !listState.canScrollForward
    LaunchedEffect(atBottom) {
        if (atBottom) showPill = false
    }
    Column(
        modifier = Modifier
            .fillMaxSize()
            .imePadding(),
    ) {
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
                text = peerLabel,
                style = MaterialTheme.typography.titleLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f),
            )
            Button(
                onClick = onSync,
                enabled = !syncing,
                modifier = Modifier.heightIn(min = SamvaadDimens.MinTouchTarget),
            ) {
                Text(if (syncing) SYNCING_LABEL else SYNC_LABEL)
            }
        }
        syncError?.let { error ->
            StatusCard(
                kind = StatusKind.Warning,
                message = error,
                modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
            )
        }
        Box(modifier = Modifier.weight(1f)) {
            if (rows == null) {
                if (failure == null) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .testTag("DetailLoading")
                            .semantics {
                                contentDescription = "Loading messages"
                            },
                        contentPadding = PaddingValues(
                            horizontal = SamvaadSpacing.Large,
                        ),
                    ) {
                        items(SKELETON_BUBBLES) { index ->
                            DetailSkeletonBubble(index)
                        }
                    }
                } else {
                    StatusCard(
                        kind = StatusKind.Error,
                        message = failure,
                        actionLabel = RETRY_LABEL,
                        // Inline lambda, not a bound reference.
                        onAction = { onRetryLoad() },
                        modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
                    )
                }
            } else if (rows.isEmpty()) {
                EmptyState(
                    title = DETAIL_EMPTY_TITLE,
                    description = DETAIL_EMPTY_DESCRIPTION,
                )
            } else {
                LazyColumn(
                    state = listState,
                    modifier = Modifier
                        .fillMaxSize()
                        .testTag("ChatDetailList"),
                    contentPadding = PaddingValues(
                        horizontal = SamvaadSpacing.Large,
                        vertical = SamvaadSpacing.Small,
                    ),
                ) {
                    itemsIndexed(
                        items = rows,
                        key = { _, row -> row.messageId },
                    ) { index, row ->
                        val previous = rows.getOrNull(index - 1)
                        val next = rows.getOrNull(index + 1)
                        val day = messageDayLabel(row.serverTimestamp)
                        val previousDay = previous?.let {
                            messageDayLabel(it.serverTimestamp)
                        }
                        if (day != null && day != previousDay) {
                            DateSeparator(label = day)
                        }
                        val continued = previous != null &&
                            previous.isOutbound == row.isOutbound &&
                            previousDay == day
                        val nextDay = next?.let { messageDayLabel(it.serverTimestamp) }
                        val groupLast = next == null ||
                            next.isOutbound != row.isOutbound ||
                            nextDay != day
                        MessageBubble(
                            row = row,
                            peerLabel = peerLabel,
                            // Sender names stay visible only when they add
                            // information (unknown/foreign senders); the
                            // header already names a 1:1 peer and every
                            // bubble announces its sender to readers.
                            showSender = !row.isOutbound &&
                                !continued &&
                                row.senderLabel != peerLabel,
                            showTime = groupLast,
                        )
                        Spacer(
                            modifier = Modifier.height(
                                if (continued) {
                                    SamvaadSpacing.XSmall
                                } else {
                                    SamvaadSpacing.Medium
                                }
                            ),
                        )
                    }
                }
            }
            if (showPill && rows != null && rows.isNotEmpty()) {
                Button(
                    // Inline lambda, not a bound reference.
                    onClick = {
                        followScope.launch {
                            listState.scrollToItem(rows.size - 1)
                            showPill = false
                        }
                    },
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .padding(bottom = SamvaadSpacing.Medium)
                        .heightIn(min = SamvaadDimens.MinTouchTarget),
                ) {
                    Text(NEW_MESSAGES_LABEL)
                }
            }
        }
        HorizontalDivider()
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
