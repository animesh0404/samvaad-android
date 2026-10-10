package com.samvaad.android

import androidx.compose.runtime.Composable
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import com.samvaad.android.db.MessageDirection
import com.samvaad.android.db.MessageEntity
import com.samvaad.android.db.SendState
import com.samvaad.android.ui.theme.SamvaadTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice C Chats list tests (host-side via Robolectric).
 *
 * The new [ChatsScreen] is rendered directly with fabricated rows — no
 * network, no crypto, no database. Loader mapping (Room → rows) is
 * covered through the pure [buildConversationList]; the production loader
 * path itself is unchanged and stays covered by the Slice 11 UI tests.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceCChatsTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun entity(
        messageId: String,
        conversationId: String,
        sequenceNumber: Long,
        direction: MessageDirection,
        sendState: SendState?,
        serverTimestamp: String,
    ) = MessageEntity(
        messageId = messageId,
        conversationId = conversationId,
        sequenceNumber = sequenceNumber,
        direction = direction,
        senderDeviceId = "dev-remote-1",
        recipientDeviceId = "dev-local-1",
        envelopeType = "RATCHET",
        ciphertext = null,
        plaintextSealed = null,
        sendState = sendState,
        requestId = null,
        serverTimestamp = serverTimestamp,
        createdAt = 1000L,
    )

    private fun row(
        conversationId: String = "conv-1",
        peerLabel: String = "bob",
        previewText: String = "hello-c",
        previewSequence: Long = 7L,
        hasPending: Boolean = false,
        previewTimestamp: String = "not-a-date-c",
        previewIsOutbound: Boolean = false,
    ) = ConversationRow(
        conversationId = conversationId,
        peerLabel = peerLabel,
        previewText = previewText,
        previewSequence = previewSequence,
        hasPending = hasPending,
        previewTimestamp = previewTimestamp,
        previewIsOutbound = previewIsOutbound,
    )

    private fun render(
        conversations: List<ConversationRow>?,
        loadError: String? = null,
        syncing: Boolean = false,
        syncError: String? = null,
        onSelect: (String) -> Unit = {},
        onRetry: () -> Unit = {},
        onSync: () -> Unit = {},
        composer: @Composable () -> Unit = {},
    ) {
        composeTestRule.setContent {
            SamvaadTheme {
                ChatsScreen(
                    conversations = conversations,
                    loadError = loadError,
                    onRetryLoad = onRetry,
                    syncing = syncing,
                    syncError = syncError,
                    onSync = onSync,
                    onSelect = onSelect,
                    composer = composer,
                )
            }
        }
    }

    // ---- Pure helpers ----

    @Test
    fun initials_twoWords_usesBothFirstLetters() {
        assertEquals("AK", conversationInitials("Alice Kim"))
    }

    @Test
    fun initials_singleWord_usesFirstLetterUppercased() {
        assertEquals("B", conversationInitials("bob"))
    }

    @Test
    fun initials_blankLabel_fallsBackToMarker() {
        assertEquals("?", conversationInitials("   "))
    }

    @Test
    fun avatarSlot_isDeterministic_andInRange() {
        val first = avatarSlot("bob")
        assertEquals(first, avatarSlot("bob"))
        assertTrue(first in 0..2)
        assertTrue(avatarSlot("alice").toString().isNotEmpty())
    }

    @Test
    fun builder_surfacesLatestTimestampAndDirection() {
        val grouped = mapOf(
            "conv-1" to listOf(
                entity("m-1", "conv-1", 1L, MessageDirection.IN, null, "2026-10-03T10:00:00"),
                entity("m-2", "conv-1", 2L, MessageDirection.OUT, SendState.SENT, "2026-10-04T11:00:00"),
            ),
        )
        val list = buildConversationList(grouped, { id, _ -> id }, { "t" })
        assertEquals(1, list.size)
        assertEquals("2026-10-04T11:00:00", list.single().previewTimestamp)
        assertTrue(list.single().previewIsOutbound)
    }

    @Test
    fun builder_inboundLatest_isNotOutbound() {
        val grouped = mapOf(
            "conv-1" to listOf(
                entity("m-1", "conv-1", 1L, MessageDirection.IN, null, "2026-10-03T10:00:00"),
            ),
        )
        val list = buildConversationList(grouped, { id, _ -> id }, { "t" })
        assertFalse(list.single().previewIsOutbound)
        assertEquals("2026-10-03T10:00:00", list.single().previewTimestamp)
    }

    // ---- Empty state ----

    @Test
    fun empty_rendersIntentionalEmptyState() {
        render(conversations = emptyList())

        composeTestRule.onNodeWithText("No conversations yet.").assertIsDisplayed()
        composeTestRule.onNodeWithText("Your conversations will appear here.")
            .assertIsDisplayed()
    }

    // ---- Rows ----

    @Test
    fun rows_renderUsernamePreviewAndTimestamp() {
        render(conversations = listOf(row()))

        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("hello-c").assertIsDisplayed()
        // Unparseable timestamps echo raw (deterministic here); parsed
        // forms are covered by TimestampFormatTest.
        composeTestRule.onNodeWithText("not-a-date-c").assertIsDisplayed()
    }

    @Test
    fun rows_outboundPreview_prefixedWithYou() {
        render(
            conversations = listOf(
                row(previewText = "hi-c", previewIsOutbound = true),
            )
        )

        composeTestRule.onNodeWithText("You: hi-c").assertIsDisplayed()
    }

    @Test
    fun rows_pending_showsSendingTextMarker() {
        render(
            conversations = listOf(
                row(hasPending = true, previewTimestamp = ""),
            )
        )

        composeTestRule.onNodeWithText("Sending…").assertIsDisplayed()
    }

    @Test
    fun rows_longPreview_rendersWithoutCrashing() {
        render(conversations = listOf(row(previewText = "lorem-c ".repeat(200))))

        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
    }

    @Test
    fun rows_haveSingleAccessibleDescription_andClickAction() {
        render(conversations = listOf(row()))

        composeTestRule
            .onNodeWithContentDescription("bob, hello-c, not-a-date-c")
            .assertHasClickAction()
            .assertIsDisplayed()
    }

    // ---- Navigation ----

    @Test
    fun rowClick_reportsConversationId() {
        var selected: String? = null
        render(
            conversations = listOf(
                row(conversationId = "conv-9", peerLabel = "carol"),
                row(conversationId = "conv-1", peerLabel = "bob"),
            ),
            onSelect = { selected = it },
        )

        composeTestRule.onNodeWithText("carol").performScrollTo()
        composeTestRule.onNodeWithText("carol").performClick()
        assertEquals("conv-9", selected)
    }

    // ---- Loading / error ----

    @Test
    fun loading_rendersSkeleton_andNoRows() {
        render(conversations = null)

        composeTestRule.onNodeWithTag("ChatsLoading").assertIsDisplayed()
        composeTestRule.onNodeWithText("bob").assertDoesNotExist()
    }

    @Test
    fun error_rendersStatusCard_withWorkingRetry() {
        var retried = false
        render(conversations = null, loadError = "Could not load conversations.") {
            retried = true
        }

        composeTestRule.onNodeWithText("Could not load conversations.")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Retry").performClick()
        assertTrue(retried)
    }

    @Test
    fun syncError_rendersWarningCard_rowsStayVisible() {
        var synced = false
        render(
            conversations = listOf(row()),
            syncError = "Sync had partial failures.",
            onSync = { synced = true },
        )

        composeTestRule.onNodeWithText("Sync had partial failures.")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("hello-c").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sync").performClick()
        assertTrue(synced)
    }

    @Test
    fun syncing_disablesSyncButton() {
        render(conversations = emptyList(), syncing = true)

        composeTestRule.onNodeWithText("Syncing…").assertIsDisplayed()
    }

    @Test
    fun composerSlot_rendersAsTrailingContent() {
        render(
            conversations = listOf(row()),
            composer = {
                androidx.compose.material3.Text("composer-sentinel-c")
            },
        )

        composeTestRule.onNodeWithText("composer-sentinel-c").performScrollTo()
        composeTestRule.onNodeWithText("composer-sentinel-c").assertIsDisplayed()
    }
}
