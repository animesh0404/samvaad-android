package com.samvaad.android

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.width as layoutWidth
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertWidthIsEqualTo
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import com.samvaad.android.ui.ds.EmptyState
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.shell.SettingsSection
import com.samvaad.android.ui.theme.SamvaadTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice H responsive/polish tests (host-side via Robolectric).
 *
 * Covers the final touch-target pass, large-font rendering, and
 * light/dark-safe behavior. The wide-window list/detail layout is
 * intentionally absent (deferred: two HomeScreen mounts would own two
 * messaging graphs/sockets); these tests pin the single-pane polish
 * that ships instead. No network, storage, or crypto on any path —
 * every composable here takes rows, not a repository.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceHResponsiveTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun row(
        conversationId: String,
        peerLabel: String,
    ) = ConversationRow(
        conversationId = conversationId,
        peerLabel = peerLabel,
        previewText = "preview-h",
        previewSequence = 1L,
        hasPending = false,
        previewTimestamp = "not-a-date-h",
        previewIsOutbound = false,
    )

    private fun message(
        messageId: String,
        text: String,
    ) = MessageRow(
        messageId = messageId,
        isOutbound = false,
        senderLabel = "bob",
        text = text,
        sequenceNumber = 1L,
        meta = "not-a-date-h",
        serverTimestamp = "not-a-date-h",
    )


    /** Large-font wrapper: forces 1.3x text scaling without new APIs. */
    @Composable
    private fun largeFont(content: @Composable () -> Unit) {
        val base = LocalDensity.current
        CompositionLocalProvider(
            LocalDensity provides Density(
                density = base.density,
                fontScale = 1.3f,
            ),
        ) {
            content()
        }
    }

    // ---- Touch targets (48dp) ----

    @Test
    fun friendsRefresh_meetsTouchTarget() {
        composeTestRule.setContent {
            SamvaadTheme {
                FriendsSection(
                    friends = emptyList(),
                    incoming = emptyList(),
                    outgoing = emptyList(),
                    loadingRoster = false,
                    rosterError = null,
                    onRefreshRoster = {},
                    addUsername = "",
                    onAddUsernameChange = {},
                    sendingRequest = false,
                    addFriendError = null,
                    addFriendSuccess = null,
                    onSendRequest = {},
                    respondingRequestId = null,
                    respondError = null,
                    onAccept = {},
                    onReject = {},
                    cancellingRequestId = null,
                    cancelError = null,
                    onCancel = {},
                    resolvingMessageUsername = null,
                    messageHint = null,
                    onMessage = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Refresh friends")
            .assertHeightIsAtLeast(48.dp)
    }

    @Test
    fun emptyStateAction_meetsTouchTarget() {
        composeTestRule.setContent {
            SamvaadTheme {
                EmptyState(
                    title = "Title h",
                    description = "Description h.",
                    actionLabel = "Retry h",
                    onAction = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Retry h")
            .assertHeightIsAtLeast(48.dp)
    }

    @Test
    fun statusCardAction_meetsTouchTarget() {
        composeTestRule.setContent {
            SamvaadTheme {
                StatusCard(
                    kind = StatusKind.Error,
                    message = "Failure h.",
                    actionLabel = "Retry h",
                    onAction = {},
                )
            }
        }

        composeTestRule.onNodeWithText("Retry h")
            .assertHeightIsAtLeast(48.dp)
    }

    @Test
    fun entryShowPassword_meetsTouchTarget() {
        // No network on mount: login only fires on Continue.
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadEntryScreen()
            }
        }

        composeTestRule.onNodeWithText("Show")
            .assertHeightIsAtLeast(48.dp)
    }

    // Wide window via qualifiers: the default Robolectric screen is
    // only 320dp, which would hide the cap (form < 480 anyway).
    @Test
    @Config(sdk = [36], qualifiers = "w800dp-h1280dp")
    fun entryForm_capsWidthOnWideWindow() {
        // Slice H: widthIn must precede fillMaxWidth, or the cap is
        // silently coerced away. The full-width Continue button exposes
        // the form column width directly.
        composeTestRule.setContent {
            SamvaadTheme {
                Box(modifier = Modifier.layoutWidth(900.dp)) {
                    SamvaadEntryScreen()
                }
            }
        }

        composeTestRule.onNodeWithText("Continue")
            .assertWidthIsEqualTo(480.dp)
    }

    // ---- Large font (1.3x) renders without loss ----

    @Test
    fun chats_rendersAtLargeFont() {
        composeTestRule.setContent {
            SamvaadTheme {
                largeFont {
                    ChatsScreen(
                        conversations = listOf(
                            row("conv-1", "bob"),
                            row("conv-2", "carol"),
                        ),
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
        }

        composeTestRule.onNodeWithText("Conversations").assertIsDisplayed()
        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
        composeTestRule.onNodeWithText("carol").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sync").assertIsDisplayed()
    }

    @Test
    fun detail_rendersAtLargeFont() {
        composeTestRule.setContent {
            SamvaadTheme {
                largeFont {
                    ChatDetailScreen(
                        peerLabel = "bob",
                        messages = listOf(
                            message("m-1", "hello h"),
                            message("m-2", "world h"),
                        ),
                        loadError = null,
                        onRetryLoad = {},
                        syncing = false,
                        syncError = null,
                        onSync = {},
                        composer = {},
                    )
                }
            }
        }

        composeTestRule.onNodeWithText("hello h").assertIsDisplayed()
        composeTestRule.onNodeWithText("world h").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sync").assertIsDisplayed()
    }

    // ---- Light/dark-safe ----

    @Test
    fun chats_rendersLight() {
        renderChats(dark = false)

        composeTestRule.onNodeWithText("Conversations").assertIsDisplayed()
        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
    }

    @Test
    fun chats_rendersDark() {
        renderChats(dark = true)

        composeTestRule.onNodeWithText("Conversations").assertIsDisplayed()
        composeTestRule.onNodeWithText("bob").assertIsDisplayed()
    }

    private fun renderChats(dark: Boolean) {
        composeTestRule.setContent {
            SamvaadTheme(darkTheme = dark) {
                ChatsScreen(
                    conversations = listOf(row("conv-1", "bob")),
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
    }

    @Test
    fun settings_rendersLight() {
        renderSettings(dark = false)

        composeTestRule.onNodeWithText("Settings").assertIsDisplayed()
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
        composeTestRule.onNodeWithText("Log out")
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun settings_rendersDark() {
        renderSettings(dark = true)

        composeTestRule.onNodeWithText("Settings").assertIsDisplayed()
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
        composeTestRule.onNodeWithText("Log out")
            .performScrollTo()
            .assertIsDisplayed()
    }

    private fun renderSettings(dark: Boolean) {
        composeTestRule.setContent {
            SamvaadTheme(darkTheme = dark) {
                SettingsSection(
                    identifier = "alice",
                    serverAddress = "https://example.invalid",
                    adopted = null,
                    onLogout = {},
                )
            }
        }
    }

    @Test
    fun friends_rendersAtLargeFont_dark() {
        composeTestRule.setContent {
            SamvaadTheme(darkTheme = true) {
                largeFont {
                    FriendsSection(
                        friends = emptyList(),
                        incoming = emptyList(),
                        outgoing = emptyList(),
                        loadingRoster = false,
                        rosterError = null,
                        onRefreshRoster = {},
                        addUsername = "",
                        onAddUsernameChange = {},
                        sendingRequest = false,
                        addFriendError = null,
                        addFriendSuccess = null,
                        onSendRequest = {},
                        respondingRequestId = null,
                        respondError = null,
                        onAccept = {},
                        onReject = {},
                        cancellingRequestId = null,
                        cancelError = null,
                        onCancel = {},
                        resolvingMessageUsername = null,
                        messageHint = null,
                        onMessage = {},
                    )
                }
            }
        }

        composeTestRule.onNodeWithText("Friends").assertIsDisplayed()
        composeTestRule.onNodeWithText("No friends yet. Add someone above.")
            .assertIsDisplayed()
    }
}
