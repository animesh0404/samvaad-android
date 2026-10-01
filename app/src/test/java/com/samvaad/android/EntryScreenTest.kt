package com.samvaad.android

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import com.samvaad.android.ui.theme.SamvaadTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Observable-behavior tests for the Slice 1 entry screen.
 *
 * Runs on the host via Robolectric. Covers branding, both inputs,
 * text entry, and Continue interaction. No networking/auth/E2EE exists.
 */
@RunWith(RobolectricTestRunner::class)
// Slice 1: pinned to SDK 36. The Compose BOM's espresso-idling-resource
// calls the hidden InputManager.getInstance(), which no longer exists in
// Robolectric's SDK 37 runtime jar.
@Config(sdk = [36])
class EntryScreenTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private fun setEntryContent() {
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadEntryScreen()
            }
        }
    }

    @Test
    fun branding_isDisplayed() {
        setEntryContent()

        composeTestRule.onNodeWithText("Samvaad").assertIsDisplayed()
    }

    @Test
    fun entryFields_exist() {
        setEntryContent()

        composeTestRule.onNodeWithText("Server address").assertIsDisplayed()
        composeTestRule.onNodeWithText("Username").assertIsDisplayed()
    }

    @Test
    fun entryFields_acceptText() {
        setEntryContent()

        composeTestRule
            .onNodeWithText("Server address")
            .performTextInput("https://samvaad.example:8080")
        composeTestRule
            .onNodeWithText("Username")
            .performTextInput("alice")

        composeTestRule
            .onNodeWithText("https://samvaad.example:8080")
            .assertIsDisplayed()
        composeTestRule.onNodeWithText("alice").assertIsDisplayed()
    }

    @Test
    fun continue_showsLocalConfirmationWithoutCrashing() {
        setEntryContent()

        composeTestRule.onNodeWithText("Continue").assertIsDisplayed()
        composeTestRule
            .onNodeWithText("Server address")
            .performTextInput("https://samvaad.example:8080")
        composeTestRule
            .onNodeWithText("Username")
            .performTextInput("alice")
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule
            .onNodeWithText("Continuing as alice on https://samvaad.example:8080")
            .assertIsDisplayed()
    }
}
