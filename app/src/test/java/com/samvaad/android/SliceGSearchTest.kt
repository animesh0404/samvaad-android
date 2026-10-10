package com.samvaad.android

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.samvaad.android.ui.theme.SamvaadTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice G search/polish tests (host-side via Robolectric).
 *
 * Local conversation search over already-loaded rows: pure filter
 * rules plus [ChatsScreen] interaction (type → filter, no-match,
 * clear, filtered navigation). No network exists on this path — the
 * composable takes rows, not a repository. Unread is intentionally
 * absent (no read state in the model) and has no tests to write.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceGSearchTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun row(
        conversationId: String,
        peerLabel: String,
        previewText: String = "preview-g",
    ) = ConversationRow(
        conversationId = conversationId,
        peerLabel = peerLabel,
        previewText = previewText,
        previewSequence = 1L,
        hasPending = false,
        previewTimestamp = "not-a-date-g",
        previewIsOutbound = false,
    )

    private val rows = listOf(
        row("conv-1", "bob", "see you tomorrow"),
        row("conv-2", "carol", "lunch plans"),
        row("conv-3", "dave", "hiking trip"),
    )

    private fun render(
        conversations: List<ConversationRow>? = rows,
        onSelect: (String) -> Unit = {},
    ) {
        composeTestRule.setContent {
            SamvaadTheme {
                ChatsScreen(
                    conversations = conversations,
                    loadError = null,
                    onRetryLoad = {},
                    syncing = false,
                    syncError = null,
                    onSync = {},
                    onSelect = onSelect,
                    composer = {},
                )
            }
        }
    }

    // ---- Pure filter ----

    @Test
    fun filter_blankQuery_returnsListUnchanged() {
        assertEquals(rows, filterConversations(rows, ""))
        assertEquals(rows, filterConversations(rows, "   "))
    }

    @Test
    fun filter_matchesPeer_caseInsensitive() {
        assertEquals(
            listOf(rows[0]),
            filterConversations(rows, "BOB"),
        )
    }

    @Test
    fun filter_matchesPreviewText() {
        assertEquals(
            listOf(rows[0]),
            filterConversations(rows, "tomorrow"),
        )
        assertEquals(
            listOf(rows[1]),
            filterConversations(rows, "lunch"),
        )
    }

    @Test
    fun filter_matchesConversationId() {
        assertEquals(
            listOf(rows[1]),
            filterConversations(rows, "conv-2"),
        )
    }

    @Test
    fun filter_noMatch_returnsEmpty() {
        assertEquals(emptyList<ConversationRow>(), filterConversations(rows, "zzz"))
    }

    // ---- UI ----

    @Test
    fun search_filtersRows_asYouType() {
        render()

        composeTestRule.onNodeWithText("Search conversations")
            .performTextInput("carol")
        // The query stays in the field, so the row resolves through its
        // unique content description.
        composeTestRule.onNodeWithContentDescription("carol, lunch plans, not-a-date-g")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("bob").assertDoesNotExist()
        composeTestRule.onNodeWithText("dave").assertDoesNotExist()
    }

    @Test
    fun search_noMatch_showsNoMatchState() {
        render()

        composeTestRule.onNodeWithText("Search conversations")
            .performTextInput("zzz-nope")
        composeTestRule.onNodeWithText("No matching conversations.")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("Try a different search.")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("bob").assertDoesNotExist()
    }

    @Test
    fun search_clear_restoresFullList() {
        render()

        composeTestRule.onNodeWithText("Search conversations")
            .performTextInput("carol")
        composeTestRule.onNodeWithText("bob").assertDoesNotExist()
        composeTestRule.onNodeWithText("Clear").performScrollTo().performClick()
        composeTestRule.onNodeWithText("bob").performScrollTo()
        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("carol").assertIsDisplayed()
        composeTestRule.onNodeWithText("dave").assertIsDisplayed()
    }

    @Test
    fun search_filteredRow_navigatesWithCorrectId() {
        var selected: String? = null
        render(onSelect = { selected = it })

        composeTestRule.onNodeWithText("Search conversations")
            .performTextInput("carol")
        composeTestRule.onNodeWithContentDescription("carol, lunch plans, not-a-date-g")
            .performClick()
        assertEquals("conv-2", selected)
    }

    @Test
    fun search_hidden_whenListEmpty_orLoading() {
        render(conversations = emptyList())
        composeTestRule.onNodeWithText("Search conversations")
            .assertDoesNotExist()
        composeTestRule.onNodeWithText("No conversations yet.")
            .assertIsDisplayed()
    }

    @Test
    fun search_hidden_whileLoading() {
        composeTestRule.setContent {
            SamvaadTheme {
                ChatsScreen(
                    conversations = null,
                    loadError = null,
                    onRetryLoad = {},
                    syncing = false,
                    syncError = null,
                    onSync = {},
                    onSelect = {},
                    composer = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Search conversations")
            .assertDoesNotExist()
    }

    @Test
    fun search_field_isAccessible_andEnabled() {
        render()

        composeTestRule.onNodeWithText("Search conversations")
            .assertIsDisplayed()
            .assertIsEnabled()
    }
}
