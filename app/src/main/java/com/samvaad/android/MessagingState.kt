package com.samvaad.android

import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.session.InboxResult
import com.samvaad.android.session.RecoverOutcome
import com.samvaad.android.session.SendFailure
import com.samvaad.android.session.SessionEstablishResult
import com.samvaad.android.session.SweepReport

/**
 * Slice 11 presentation mapping: durable Room rows → UI rows.
 *
 * Pure functions only (no Android framework, no network, no crypto
 * except through the injected [openText]/lookup lambdas), so host tests
 * cover the ordering/preview/label/error rules directly. Composables
 * render these rows; loading/reload stays in [HomeScreen].
 *
 * Nothing here persists, logs, or otherwise retains message content:
 * unsealed text flows caller → row → Compose state (memory only).
 */

/** One conversation-list row, derived from durable local messages. */
data class ConversationRow(
    val conversationId: String,
    val peerLabel: String,
    val previewText: String,
    val previewSequence: Long,
    /** True when an outbound row is not yet server-accepted. */
    val hasPending: Boolean,
    /**
     * Raw server timestamp of the latest row (`""` when the server has
     * not accepted it yet). Presented through `formatServerTimestamp`;
     * never parsed or persisted here.
     */
    val previewTimestamp: String,
    /** True when the latest row is outbound (rendered with a "You:" prefix). */
    val previewIsOutbound: Boolean,
)

/** One rendered message row. [text] is memory-only unsealed plaintext. */
data class MessageRow(
    val messageId: String,
    val isOutbound: Boolean,
    val senderLabel: String,
    val text: String,
    val sequenceNumber: Long,
    /** "Sending…" for unaccepted outbound rows, else the server timestamp. */
    val meta: String,
    /**
     * Raw server timestamp of this row (`""` when the server has not
     * accepted it yet). Presentation only: day separators and bubble
     * captions derive from it without touching persistence.
     */
    val serverTimestamp: String,
)

/** Fixed placeholder when sealed content cannot be opened. Never logged. */
const val MESSAGE_UNREADABLE = "This message could not be displayed."

/** Fallback sender label when no session metadata names the device. */
const val UNKNOWN_SENDER_LABEL = "Unknown sender"

/** Own-device sender label. */
const val OWN_SENDER_LABEL = "You"

/** Outbound rows not yet server-accepted. */
const val SENDING_LABEL = "Sending…"

/** Upper bound for one detail/preview read. Room has no backward pages. */
const val MESSAGE_PAGE_LIMIT = 500

/** Tail window used for conversation previews. */
const val PREVIEW_TAIL_LIMIT = 50

/**
 * Build the conversation list from durable rows keyed by conversation.
 * Excludes the outbound pre-acceptance sentinel (`""`), skips empty
 * groups, previews the latest durable sequence, orders by that sequence
 * descending. Pure: callers supply Room rows plus label/text resolvers.
 */
fun buildConversationList(
    rowsByConversation: Map<String, List<MessageEntity>>,
    peerLabel: (conversationId: String, rows: List<MessageEntity>) -> String,
    previewText: (MessageEntity) -> String,
): List<ConversationRow> {
    return rowsByConversation
        .filterKeys { it.isNotEmpty() }
        .mapNotNull { (conversationId, rows) ->
            val latest = rows.maxByOrNull { it.sequenceNumber } ?: return@mapNotNull null
            ConversationRow(
                conversationId = conversationId,
                peerLabel = peerLabel(conversationId, rows),
                previewText = previewText(latest),
                previewSequence = latest.sequenceNumber,
                hasPending = rows.any {
                    it.direction == MessageDirection.OUT && it.sendState != SendState.SENT
                },
                previewTimestamp = latest.serverTimestamp,
                previewIsOutbound = latest.direction == MessageDirection.OUT,
            )
        }
        .sortedByDescending { it.previewSequence }
}

/**
 * Map one durable row to a rendered row. Unseals at read time through
 * [openText]; any failure (null/blank) renders the fixed placeholder —
 * fail closed, never blank, never raw bytes.
 */
fun mapMessageRow(
    entity: MessageEntity,
    senderLabel: String,
    openText: (messageId: String, sealed: ByteArray) -> String?,
): MessageRow {
    val text = entity.plaintextSealed
        ?.let { openText(entity.messageId, it) }
        ?.takeIf { it.isNotEmpty() }
        ?: MESSAGE_UNREADABLE
    val meta = if (entity.direction == MessageDirection.OUT &&
        entity.sendState != SendState.SENT
    ) {
        SENDING_LABEL
    } else {
        entity.serverTimestamp.ifEmpty { "Sent" }
    }
    return MessageRow(
        messageId = entity.messageId,
        isOutbound = entity.direction == MessageDirection.OUT,
        senderLabel = senderLabel,
        text = text,
        sequenceNumber = entity.sequenceNumber,
        meta = meta,
        serverTimestamp = entity.serverTimestamp,
    )
}

/**
 * Resolve the peer label for a conversation from its rows: the remote
 * device on either side, resolved through session metadata. Falls back
 * to the conversation ID — never a guessed username.
 */
fun peerLabelFor(
    conversationId: String,
    rows: List<MessageEntity>,
    lookupUsername: (deviceId: String) -> String?,
): String {
    val remoteId = rows.firstOrNull()?.let { row ->
        if (row.direction == MessageDirection.OUT) {
            row.recipientDeviceId
        } else {
            row.senderDeviceId
        }
    }.orEmpty()
    if (remoteId.isEmpty()) return conversationId
    return lookupUsername(remoteId) ?: conversationId
}

/**
 * Resolve the sender label for one row: own outbound rows are "You",
 * inbound rows resolve through session metadata, unknown devices render
 * an explicit unknown marker — never a guessed username.
 */
fun senderLabelFor(
    entity: MessageEntity,
    lookupUsername: (deviceId: String) -> String?,
): String {
    if (entity.direction == MessageDirection.OUT) return OWN_SENDER_LABEL
    return lookupUsername(entity.senderDeviceId) ?: UNKNOWN_SENDER_LABEL
}

/** Fixed safe message for every send failure. Internal reasons never surface. */
fun sendFailureMessage(kind: SendFailure): String = when (kind) {
    SendFailure.CryptoUnavailable ->
        "Messaging is unavailable on this installation."
    is SendFailure.SessionUnavailable ->
        "No session with this device yet. Establish it and try again."
    SendFailure.IdentityMismatch ->
        "The contact's identity changed. Stopped for safety."
    SendFailure.TransportRetryable ->
        "Could not reach the server. The message is saved and will be retried on Sync."
    SendFailure.Unauthorized ->
        "Your sign-in expired. Sign in again and retry."
    SendFailure.Forbidden ->
        "The server refused this message."
    SendFailure.NotFound ->
        "The recipient device is no longer available."
    SendFailure.Conflict ->
        "The server rejected this message. Please try again."
    SendFailure.BadRequest ->
        "The server rejected this message."
    is SendFailure.Rejected ->
        "The server rejected this message."
}

/**
 * Fixed safe message for establishment failures; null when [Established].
 * The directory/claim reasons stay internal.
 */
fun establishFailureMessage(result: SessionEstablishResult): String? = when (result) {
    is SessionEstablishResult.Established -> null
    SessionEstablishResult.NoDevices ->
        "That user has no active devices."
    is SessionEstablishResult.DeviceNotFound ->
        "That device is no longer available for this user."
    SessionEstablishResult.DeviceNotActive ->
        "That device is no longer available."
    SessionEstablishResult.NotFriends ->
        "You can only message friends."
    SessionEstablishResult.TargetNotFound ->
        "User not found. Check the name and try again."
    SessionEstablishResult.Unauthorized ->
        "Your sign-in expired. Sign in again and retry."
    SessionEstablishResult.ClaimConflict ->
        "Could not establish a session. Please try again."
    SessionEstablishResult.KyberUnsupported ->
        "That device does not support current encryption. Cannot proceed."
    SessionEstablishResult.IdentityMismatch ->
        "The contact's identity changed. Stopped for safety."
    is SessionEstablishResult.SessionUnavailable ->
        "A session could not be established. Please try again."
    SessionEstablishResult.CryptoUnavailable ->
        "Messaging is unavailable on this installation."
    SessionEstablishResult.TransportRetryable ->
        "Could not reach the server. Check the connection and try again."
    is SessionEstablishResult.InvalidBundle ->
        "Could not establish a session. Please try again."
    is SessionEstablishResult.Rejected ->
        "The server refused this request."
}

/** Fixed safe message when a manual Sync partially fails; null when clean. */
fun sweepErrorMessage(report: SweepReport): String? {
    // Note: recoverInbox reports a null branch error when receive()
    // returns Failed (transport/unreachable) instead of throwing, so a
    // failed inbox result itself counts as a partial failure here. This
    // only widens UI surfacing; sweep semantics are unchanged.
    val failed = report.outboxError != null ||
        report.inbox is InboxResult.Failed ||
        report.inboxError != null ||
        report.historyError != null ||
        report.cursorError != null ||
        report.outboxRecovered.any { it is RecoverOutcome.RowFailed }
    return if (failed) {
        "Sync had partial failures. Your messages are safe; try Sync again."
    } else {
        null
    }
}
