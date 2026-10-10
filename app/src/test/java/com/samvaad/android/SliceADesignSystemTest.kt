package com.samvaad.android

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import com.samvaad.android.ui.ds.EmptyState
import com.samvaad.android.ui.ds.SamvaadTextField
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.theme.SamvaadTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice A design-primitive tests (host-side via Robolectric).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class SliceADesignSystemTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    @Test
    fun textField_acceptsInput() {
        composeTestRule.setContent {
            var text by remember { mutableStateOf("") }
            SamvaadTheme {
                SamvaadTextField(
                    value = text,
                    onValueChange = { text = it },
                    label = "Server address",
                )
            }
        }

        composeTestRule.onNodeWithText("Server address").performTextInput("https://x:8080")
        composeTestRule.onNodeWithText("https://x:8080").assertIsDisplayed()
    }

    @Test
    fun textField_disabled_isNotEnabled() {
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadTextField(
                    value = "",
                    onValueChange = {},
                    label = "Username",
                    enabled = false,
                )
            }
        }

        composeTestRule.onNodeWithText("Username").assertIsNotEnabled()
    }

    @Test
    fun textField_errorText_isDisplayed() {
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadTextField(
                    value = "bad",
                    onValueChange = {},
                    label = "Username",
                    errorText = "That name is not available.",
                )
            }
        }

        composeTestRule.onNodeWithText("That name is not available.").assertIsDisplayed()
        composeTestRule
            .onNode(
                SemanticsMatcher.expectValue(
                    SemanticsProperties.Error,
                    "That name is not available.",
                )
            )
            .assertExists()
    }

    @Test
    fun textField_supportingText_isDisplayed() {
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadTextField(
                    value = "",
                    onValueChange = {},
                    label = "Server address",
                    supportingText = "Starting with https://",
                )
            }
        }

        composeTestRule.onNodeWithText("Starting with https://").assertIsDisplayed()
    }

    @Test
    fun textField_passwordToggle_flipsTrailingLabel() {
        var hidden by mutableStateOf(true)
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadTextField(
                    value = "s3cr3t!",
                    onValueChange = {},
                    label = "Password",
                    visualTransformation = if (hidden) {
                        PasswordVisualTransformation()
                    } else {
                        VisualTransformation.None
                    },
                    trailingContent = {
                        androidx.compose.material3.TextButton(
                            onClick = { hidden = !hidden }
                        ) {
                            androidx.compose.material3.Text(if (hidden) "Show" else "Hide")
                        }
                    },
                )
            }
        }

        composeTestRule.onNodeWithText("Show").performClick()
        composeTestRule.onNodeWithText("Hide").assertIsDisplayed()
        composeTestRule.onNodeWithText("Hide").performClick()
        composeTestRule.onNodeWithText("Show").assertIsDisplayed()
    }

    @Test
    fun statusCard_info_displaysMessage() {
        composeTestRule.setContent {
            SamvaadTheme {
                StatusCard(kind = StatusKind.Info, message = "All systems normal.")
            }
        }
        composeTestRule.onNodeWithText("All systems normal.").assertIsDisplayed()
    }

    @Test
    fun statusCard_warning_displaysTitleAndMessage() {
        composeTestRule.setContent {
            SamvaadTheme {
                StatusCard(
                    kind = StatusKind.Warning,
                    title = "Heads up",
                    message = "Sync is slow today.",
                )
            }
        }
        composeTestRule.onNodeWithText("Heads up").assertIsDisplayed()
        composeTestRule.onNodeWithText("Sync is slow today.").assertIsDisplayed()
    }

    @Test
    fun statusCard_error_exposesErrorSemantics_andAction() {
        var acted = false
        composeTestRule.setContent {
            SamvaadTheme {
                StatusCard(
                    kind = StatusKind.Error,
                    message = "Sign in failed.",
                    actionLabel = "Retry",
                    onAction = { acted = true },
                )
            }
        }

        composeTestRule.onNodeWithText("Sign in failed.").assertIsDisplayed()
        composeTestRule
            .onNode(SemanticsMatcher.expectValue(SemanticsProperties.Error, "Sign in failed."))
            .assertExists()
        composeTestRule.onNodeWithText("Retry").assertIsEnabled()
        composeTestRule.onNodeWithText("Retry").performClick()
        assertTrue(acted)
    }

    @Test
    fun statusCard_success_displaysMessage() {
        composeTestRule.setContent {
            SamvaadTheme {
                StatusCard(kind = StatusKind.Success, message = "Request sent.")
            }
        }
        composeTestRule.onNodeWithText("Request sent.").assertIsDisplayed()
    }

    @Test
    fun emptyState_rendersTitleDescriptionAndCta() {
        var acted = false
        composeTestRule.setContent {
            SamvaadTheme {
                EmptyState(
                    title = "No conversations yet",
                    description = "Add a friend to start chatting.",
                    actionLabel = "Add friend",
                    onAction = { acted = true },
                )
            }
        }

        composeTestRule.onNodeWithText("No conversations yet").assertIsDisplayed()
        composeTestRule.onNodeWithText("Add a friend to start chatting.").assertIsDisplayed()
        composeTestRule.onNodeWithText("Add friend").performClick()
        assertTrue(acted)
    }

    @Test
    fun emptyState_withoutAction_rendersNoButton() {
        composeTestRule.setContent {
            SamvaadTheme {
                EmptyState(
                    title = "Nothing here",
                    description = "Try again later.",
                )
            }
        }

        composeTestRule.onNodeWithText("Nothing here").assertIsDisplayed()
        composeTestRule.onNodeWithText("Try again later.").assertIsDisplayed()
    }
}
