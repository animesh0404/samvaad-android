package com.samvaad.android

import androidx.compose.foundation.background
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import com.samvaad.android.friends.FriendEntry
import com.samvaad.android.friends.FriendRequestRecord
import com.samvaad.android.ui.ds.EmptyState
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadShapes
import com.samvaad.android.ui.theme.SamvaadSpacing
import com.samvaad.android.ui.util.formatServerTimestamp

/**
 * Friends destination renderer (Slice D rehaul; Slice 14 behavior kept).
 *
 * Pure presentation like [ComposerUi]: all state lives in HomeScreen,
 * this file only renders. Server usernames are display strings; tokens
 * never reach here.
 *
 * Data actually available per item — nothing more:
 * - incoming/outgoing requests: usernames both ends, opaque [createdAt]
 *   (display-only via [formatServerTimestamp], hidden when blank), and
 *   the PENDING status the list endpoint guarantees;
 * - accepted friends: userId + username only — no timestamps, no
 *   conversation IDs, no avatars. Rows therefore show relationship
 *   metadata ("Friend"), never fabricated dates or IDs.
 *
 * Legacy strings ("Friends", "New friend username", "Add friend",
 * "No friends yet. Add someone above.", "Friend requests",
 * "Request from …", "Accept"/"Reject", "Refresh friends") are preserved
 * verbatim: existing flows and tests depend on them.
 */

/** Legacy strings, preserved verbatim. */
private const val FRIENDS_TITLE = "Friends"
private const val ADD_USERNAME_LABEL = "New friend username"
private const val ADD_LABEL = "Add friend"
private const val SENDING_REQUEST_LABEL = "Sending…"
private const val EMPTY_TITLE = "No friends yet. Add someone above."
private const val EMPTY_DESCRIPTION = "Send a request above to start messaging."
private const val INCOMING_HEADER = "Friend requests"
private const val REFRESH_LABEL = "Refresh friends"

/** New Slice D strings. */
private const val OUTGOING_HEADER = "Outgoing requests"
private const val ACCEPTED_HEADER = "Accepted friends"
private const val ACCEPT_LABEL = "Accept"
private const val ACCEPTING_LABEL = "Accepting…"
private const val DECLINE_LABEL = "Reject"
private const val CANCEL_LABEL = "Cancel"
private const val CANCELLING_LABEL = "Cancelling…"
private const val MESSAGE_LABEL = "Message"
private const val OPENING_LABEL = "Opening…"
private const val FRIEND_SUBTITLE = "Friend"
private const val PENDING_SUBTITLE = "Request pending"

@Composable
private fun FriendsSkeletonRow() {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.Small,
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
                    .fillMaxWidth(fraction = 0.4f)
                    .height(SamvaadSpacing.Large)
                    .clip(SamvaadShapes.small)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            )
            Box(
                modifier = Modifier
                    .fillMaxWidth(fraction = 0.7f)
                    .height(SamvaadSpacing.Medium)
                    .clip(SamvaadShapes.small)
                    .background(MaterialTheme.colorScheme.surfaceVariant),
            )
        }
    }
}

private const val SKELETON_ROWS = 3

/** "Requested 05 Oct", or "" when the request carries no timestamp. */
private fun requestedLine(createdAt: String?): String {
    val formatted = formatServerTimestamp(createdAt)
    return if (formatted.isEmpty()) "" else "Requested $formatted"
}

@Composable
private fun IncomingRequestRow(
    request: FriendRequestRecord,
    busy: Boolean,
    accepting: Boolean,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.Small,
            )
            // State in words for screen readers; children keep their own
            // nodes so text queries stay unambiguous (two actions merge
            // poorly under mergeDescendants).
            .semantics {
                contentDescription =
                    "${request.senderUsername}, incoming friend request"
            },
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            ConversationAvatar(label = request.senderUsername)
            Spacer(modifier = Modifier.width(SamvaadSpacing.Medium))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Request from ${request.senderUsername}",
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val secondary = requestedLine(request.createdAt)
                if (secondary.isNotEmpty()) {
                    Text(
                        text = secondary,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
        }
        Spacer(modifier = Modifier.height(SamvaadSpacing.Small))
        Row(
            horizontalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Button(
                // Inline lambda, not a bound reference (Slice B finding).
                onClick = { onAccept(request.requestId) },
                enabled = !busy,
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = SamvaadDimens.MinTouchTarget)
                    .semantics {
                        contentDescription =
                            "Accept friend request from ${request.senderUsername}"
                    },
            ) {
                Text(if (accepting) ACCEPTING_LABEL else ACCEPT_LABEL)
            }
            OutlinedButton(
                onClick = { onReject(request.requestId) },
                enabled = !busy,
                modifier = Modifier
                    .weight(1f)
                    .heightIn(min = SamvaadDimens.MinTouchTarget)
                    .semantics {
                        contentDescription =
                            "Reject friend request from ${request.senderUsername}"
                    },
            ) {
                Text(DECLINE_LABEL)
            }
        }
    }
}

@Composable
private fun OutgoingRequestRow(
    request: FriendRequestRecord,
    busy: Boolean,
    cancelling: Boolean,
    onCancel: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.Small,
            )
            .semantics {
                contentDescription =
                    "${request.recipientUsername}, outgoing friend request, pending"
            },
    ) {
        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.fillMaxWidth(),
        ) {
            ConversationAvatar(label = request.recipientUsername)
            Spacer(modifier = Modifier.width(SamvaadSpacing.Medium))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = request.recipientUsername,
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                val timestamp = formatServerTimestamp(request.createdAt)
                Text(
                    text = if (timestamp.isEmpty()) {
                        PENDING_SUBTITLE
                    } else {
                        "$PENDING_SUBTITLE · $timestamp"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
        }
        Spacer(modifier = Modifier.height(SamvaadSpacing.Small))
        OutlinedButton(
            // Inline lambda, not a bound reference (Slice B finding).
            onClick = { onCancel(request.requestId) },
            enabled = !busy,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = SamvaadDimens.MinTouchTarget)
                .semantics {
                    contentDescription =
                        "Cancel friend request to ${request.recipientUsername}"
                },
        ) {
            Text(if (cancelling) CANCELLING_LABEL else CANCEL_LABEL)
        }
    }
}

@Composable
private fun AcceptedFriendRow(
    friend: FriendEntry,
    resolving: Boolean,
    onMessage: (String) -> Unit,
) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.Small,
            )
            .semantics {
                contentDescription = "${friend.username}, friend"
            },
    ) {
        ConversationAvatar(label = friend.username)
        Spacer(modifier = Modifier.width(SamvaadSpacing.Medium))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = friend.username,
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = FRIEND_SUBTITLE,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(modifier = Modifier.width(SamvaadSpacing.Small))
        Button(
            // Inline lambda, not a bound reference (Slice B finding).
            onClick = { onMessage(friend.username) },
            enabled = !resolving,
            modifier = Modifier
                .heightIn(min = SamvaadDimens.MinTouchTarget)
                .semantics {
                    contentDescription = "Message ${friend.username}"
                },
        ) {
            Text(if (resolving) OPENING_LABEL else MESSAGE_LABEL)
        }
    }
}

@Composable
private fun SectionHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(
            horizontal = SamvaadSpacing.Large,
            vertical = SamvaadSpacing.XSmall,
        ),
    )
}

@Composable
private fun FriendsTitle() {
    Text(
        text = FRIENDS_TITLE,
        style = MaterialTheme.typography.titleMedium,
        modifier = Modifier.padding(
            horizontal = SamvaadSpacing.Large,
            vertical = SamvaadSpacing.Small,
        ),
    )
}

@Composable
private fun AddFriendBlock(
    addUsername: String,
    onAddUsernameChange: (String) -> Unit,
    sendingRequest: Boolean,
    addFriendError: String?,
    addFriendSuccess: String?,
    onSendRequest: () -> Unit,
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.Small),
        modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
    ) {
        OutlinedTextField(
            value = addUsername,
            onValueChange = onAddUsernameChange,
            // Distinct from the composer "Friend username": both
            // render on the same screen once messaging is available.
            label = { Text(ADD_USERNAME_LABEL) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Button(
            onClick = onSendRequest,
            enabled = !sendingRequest && addUsername.isNotBlank(),
            modifier = Modifier.heightIn(min = SamvaadDimens.MinTouchTarget),
        ) {
            Text(if (sendingRequest) SENDING_REQUEST_LABEL else ADD_LABEL)
        }
        if (addFriendError != null) {
            Text(
                text = addFriendError,
                color = MaterialTheme.colorScheme.error
            )
        }
        if (addFriendSuccess != null) {
            Text(
                text = addFriendSuccess,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun FriendsLoadingBlock() {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("FriendsLoading")
            .semantics {
                contentDescription = "Loading friends"
            },
    ) {
        repeat(SKELETON_ROWS) { FriendsSkeletonRow() }
    }
}

@Composable
private fun RosterErrorBlock(rosterError: String) {
    StatusCard(
        kind = StatusKind.Error,
        message = rosterError,
        modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
    )
}

@Composable
private fun RefreshBlock(onRefreshRoster: () -> Unit) {
    TextButton(
        // Inline lambda, not a bound reference.
        onClick = { onRefreshRoster() },
        modifier = Modifier
            .padding(horizontal = SamvaadSpacing.Small)
            // Slice H: refresh meets the 48dp touch target.
            .heightIn(min = SamvaadDimens.MinTouchTarget),
    ) {
        Text(REFRESH_LABEL)
    }
}

@Composable
fun FriendsSection(
    friends: List<FriendEntry>?,
    incoming: List<FriendRequestRecord>?,
    outgoing: List<FriendRequestRecord>?,
    loadingRoster: Boolean,
    rosterError: String?,
    onRefreshRoster: () -> Unit,
    addUsername: String,
    onAddUsernameChange: (String) -> Unit,
    sendingRequest: Boolean,
    addFriendError: String?,
    addFriendSuccess: String?,
    onSendRequest: () -> Unit,
    respondingRequestId: String?,
    respondError: String?,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
    cancellingRequestId: String?,
    cancelError: String?,
    onCancel: (String) -> Unit,
    resolvingMessageUsername: String?,
    messageHint: String?,
    onMessage: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .testTag("FriendsList"),
    ) {
        item(key = "header") {
            FriendsTitle()
        }
        item(key = "add") {
            AddFriendBlock(
                addUsername = addUsername,
                onAddUsernameChange = onAddUsernameChange,
                sendingRequest = sendingRequest,
                addFriendError = addFriendError,
                addFriendSuccess = addFriendSuccess,
                onSendRequest = onSendRequest,
            )
        }
        if (loadingRoster) {
            item(key = "loading") {
                FriendsLoadingBlock()
            }
        } else {
            loadedItems(
                friends = friends,
                incoming = incoming,
                outgoing = outgoing,
                rosterError = rosterError,
                respondingRequestId = respondingRequestId,
                respondError = respondError,
                onAccept = onAccept,
                onReject = onReject,
                cancellingRequestId = cancellingRequestId,
                cancelError = cancelError,
                onCancel = onCancel,
                resolvingMessageUsername = resolvingMessageUsername,
                messageHint = messageHint,
                onMessage = onMessage,
            )
            item(key = "refresh") {
                RefreshBlock(onRefreshRoster)
            }
        }
    }
}

/**
 * Loaded-state content for the lazy destination. Item wrappers live
 * here so the same rows can also back the non-lazy legacy container
 * ([loadedColumnContent]) used inside the Full-mode scroll, where an
 * unbounded LazyColumn would crash.
 */
private fun androidx.compose.foundation.lazy.LazyListScope.loadedItems(
    friends: List<FriendEntry>?,
    incoming: List<FriendRequestRecord>?,
    outgoing: List<FriendRequestRecord>?,
    rosterError: String?,
    respondingRequestId: String?,
    respondError: String?,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
    cancellingRequestId: String?,
    cancelError: String?,
    onCancel: (String) -> Unit,
    resolvingMessageUsername: String?,
    messageHint: String?,
    onMessage: (String) -> Unit,
) {
    val pending = incoming
    if (!pending.isNullOrEmpty()) {
        item(key = "incoming-header") {
            SectionHeader(INCOMING_HEADER)
        }
        val busy = respondingRequestId != null
        items(
            items = pending,
            key = { it.requestId },
        ) { request ->
            IncomingRequestRow(
                request = request,
                busy = busy,
                accepting = respondingRequestId == request.requestId,
                // Inline lambdas, not bound references.
                onAccept = { onAccept(it) },
                onReject = { onReject(it) },
            )
        }
    }
    val sent = outgoing
    if (!sent.isNullOrEmpty()) {
        item(key = "outgoing-header") {
            SectionHeader(OUTGOING_HEADER)
        }
        val busy = cancellingRequestId != null
        items(
            items = sent,
            key = { it.requestId },
        ) { request ->
            OutgoingRequestRow(
                request = request,
                busy = busy,
                cancelling = cancellingRequestId == request.requestId,
                // Inline lambda, not a bound reference.
                onCancel = { onCancel(it) },
            )
        }
    }
    rosterBlockItems(
        friends = friends,
        rosterError = rosterError,
        resolvingMessageUsername = resolvingMessageUsername,
        onMessage = onMessage,
    )
    operationErrorsItems(
        respondError = respondError,
        cancelError = cancelError,
        messageHint = messageHint,
    )
}

private fun androidx.compose.foundation.lazy.LazyListScope.rosterBlockItems(
    friends: List<FriendEntry>?,
    rosterError: String?,
    resolvingMessageUsername: String?,
    onMessage: (String) -> Unit,
) {
    val roster = friends
    if (roster == null) {
        if (rosterError != null) {
            item(key = "roster-error") {
                RosterErrorBlock(rosterError)
            }
        }
    } else if (roster.isEmpty()) {
        item(key = "empty") {
            FriendsEmptyBlock()
        }
    } else {
        item(key = "accepted-header") {
            SectionHeader(ACCEPTED_HEADER)
        }
        items(
            items = roster,
            key = { it.userId },
        ) { friend ->
            AcceptedFriendRow(
                friend = friend,
                resolving = resolvingMessageUsername == friend.username,
                // Inline lambda, not a bound reference.
                onMessage = { onMessage(it) },
            )
        }
    }
}

private fun androidx.compose.foundation.lazy.LazyListScope.operationErrorsItems(
    respondError: String?,
    cancelError: String?,
    messageHint: String?,
) {
    if (respondError != null) {
        item(key = "respond-error") {
            StatusCard(
                kind = StatusKind.Error,
                message = respondError,
                modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
            )
        }
    }
    if (cancelError != null) {
        item(key = "cancel-error") {
            StatusCard(
                kind = StatusKind.Error,
                message = cancelError,
                modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
            )
        }
    }
    if (messageHint != null) {
        item(key = "message-hint") {
            StatusCard(
                kind = StatusKind.Warning,
                message = messageHint,
                modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
            )
        }
    }
}

@Composable
private fun FriendsEmptyBlock() {
    EmptyState(
        title = EMPTY_TITLE,
        description = EMPTY_DESCRIPTION,
    )
}

/**
 * Non-lazy rendering of the same Friends content for the Full
 * (legacy) scroll, where an unbounded LazyColumn would crash. Same
 * pieces, same order, same strings — only the container differs.
 */
@Composable
fun FriendsColumn(
    friends: List<FriendEntry>?,
    incoming: List<FriendRequestRecord>?,
    outgoing: List<FriendRequestRecord>?,
    loadingRoster: Boolean,
    rosterError: String?,
    onRefreshRoster: () -> Unit,
    addUsername: String,
    onAddUsernameChange: (String) -> Unit,
    sendingRequest: Boolean,
    addFriendError: String?,
    addFriendSuccess: String?,
    onSendRequest: () -> Unit,
    respondingRequestId: String?,
    respondError: String?,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
    cancellingRequestId: String?,
    cancelError: String?,
    onCancel: (String) -> Unit,
    resolvingMessageUsername: String?,
    messageHint: String?,
    onMessage: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("FriendsList"),
    ) {
        FriendsTitle()
        AddFriendBlock(
            addUsername = addUsername,
            onAddUsernameChange = onAddUsernameChange,
            sendingRequest = sendingRequest,
            addFriendError = addFriendError,
            addFriendSuccess = addFriendSuccess,
            onSendRequest = onSendRequest,
        )
        if (loadingRoster) {
            FriendsLoadingBlock()
        } else {
            loadedColumnContent(
                friends = friends,
                incoming = incoming,
                outgoing = outgoing,
                rosterError = rosterError,
                respondingRequestId = respondingRequestId,
                respondError = respondError,
                onAccept = onAccept,
                onReject = onReject,
                cancellingRequestId = cancellingRequestId,
                cancelError = cancelError,
                onCancel = onCancel,
                resolvingMessageUsername = resolvingMessageUsername,
                messageHint = messageHint,
                onMessage = onMessage,
            )
            RefreshBlock(onRefreshRoster)
        }
    }
}

@Composable
private fun loadedColumnContent(
    friends: List<FriendEntry>?,
    incoming: List<FriendRequestRecord>?,
    outgoing: List<FriendRequestRecord>?,
    rosterError: String?,
    respondingRequestId: String?,
    respondError: String?,
    onAccept: (String) -> Unit,
    onReject: (String) -> Unit,
    cancellingRequestId: String?,
    cancelError: String?,
    onCancel: (String) -> Unit,
    resolvingMessageUsername: String?,
    messageHint: String?,
    onMessage: (String) -> Unit,
) {
    val pending = incoming
    if (!pending.isNullOrEmpty()) {
        SectionHeader(INCOMING_HEADER)
        val busy = respondingRequestId != null
        pending.forEach { request ->
            IncomingRequestRow(
                request = request,
                busy = busy,
                accepting = respondingRequestId == request.requestId,
                // Inline lambdas, not bound references.
                onAccept = { onAccept(it) },
                onReject = { onReject(it) },
            )
        }
    }
    val sent = outgoing
    if (!sent.isNullOrEmpty()) {
        SectionHeader(OUTGOING_HEADER)
        val busy = cancellingRequestId != null
        sent.forEach { request ->
            OutgoingRequestRow(
                request = request,
                busy = busy,
                cancelling = cancellingRequestId == request.requestId,
                // Inline lambda, not a bound reference.
                onCancel = { onCancel(it) },
            )
        }
    }
    val roster = friends
    if (roster == null) {
        if (rosterError != null) {
            RosterErrorBlock(rosterError)
        }
    } else if (roster.isEmpty()) {
        FriendsEmptyBlock()
    } else {
        SectionHeader(ACCEPTED_HEADER)
        roster.forEach { friend ->
            AcceptedFriendRow(
                friend = friend,
                resolving = resolvingMessageUsername == friend.username,
                // Inline lambda, not a bound reference.
                onMessage = { onMessage(it) },
            )
        }
    }
    if (respondError != null) {
        StatusCard(
            kind = StatusKind.Error,
            message = respondError,
            modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
        )
    }
    if (cancelError != null) {
        StatusCard(
            kind = StatusKind.Error,
            message = cancelError,
            modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
        )
    }
    if (messageHint != null) {
        StatusCard(
            kind = StatusKind.Warning,
            message = messageHint,
            modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
        )
    }
}
