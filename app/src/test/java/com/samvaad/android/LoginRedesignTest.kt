package com.samvaad.android

import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import com.samvaad.android.ui.theme.SamvaadTheme
import java.io.IOException
import java.util.concurrent.CountDownLatch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Slice A login-redesign tests: new presentation behavior only.
 * Authentication semantics stay covered by [EntryScreenTest].
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class LoginRedesignTest {

    @get:Rule
    val composeTestRule = createComposeRule()

    private class FakeAuthApi : AuthApi {
        var result: Result<AuthSession> = Result.success(
            AuthSession(
                identifier = "alice",
                accessToken = "access-1",
                refreshToken = "refresh-1",
                sessionId = "session-1",
            )
        )
        var gate: CountDownLatch? = null

        override suspend fun login(request: LoginRequest): AuthSession {
            withContext(Dispatchers.IO) {
                gate?.await()
            }
            return result.getOrThrow()
        }

        override suspend fun refresh(
            serverAddress: String,
            refreshToken: String,
        ): RefreshedSession = throw AssertionError("unexpected refresh")

        override suspend fun logout(serverAddress: String, accessToken: String) {
            throw AssertionError("unexpected logout")
        }
    }

    private fun setEntryContent(fake: FakeAuthApi = FakeAuthApi()) {
        composeTestRule.setContent {
            SamvaadTheme {
                SamvaadEntryScreen(authApi = fake)
            }
        }
    }

    private fun fillValidForm() {
        composeTestRule
            .onNodeWithText("Server address")
            .performTextInput("https://samvaad.example:8080/")
        composeTestRule
            .onNodeWithText("Username")
            .performTextInput("alice")
        composeTestRule
            .onNodeWithText("Password")
            .performTextInput("s3cr3t!")
    }

    @Test
    fun supportingCopy_isDisplayed() {
        setEntryContent()

        composeTestRule.onNodeWithText("Samvaad").assertIsDisplayed()
        composeTestRule
            .onNodeWithText("Private messaging for you and your friends.", substring = true)
            .assertIsDisplayed()
    }

    @Test
    fun passwordToggle_revealsAndHidesPassword() {
        setEntryContent()
        composeTestRule.onNodeWithText("Password").performTextInput("s3cr3t!")

        // The toggle flips its label; the actual glyph obscuring is the
        // framework PasswordVisualTransformation (semantics keep raw text).
        composeTestRule.onNodeWithText("Show").performScrollTo()
        composeTestRule.onNodeWithText("Show").performClick()
        composeTestRule.onNodeWithText("Hide").assertIsDisplayed()

        composeTestRule.onNodeWithText("Hide").performClick()
        composeTestRule.onNodeWithText("Show").assertIsDisplayed()
    }

    @Test
    fun loading_disablesForm() {
        val fake = FakeAuthApi()
        fake.gate = CountDownLatch(1)
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule.onNodeWithText("Server address").assertIsNotEnabled()
        composeTestRule.onNodeWithText("Continue").assertIsNotEnabled()

        fake.gate!!.countDown()
        composeTestRule
            .onNodeWithText("Signed in as alice")
            .performScrollTo()
        composeTestRule.onNodeWithText("Signed in as alice").assertIsDisplayed()
    }

    @Test
    fun failedLogin_errorCard_exposesErrorSemantics() {
        val fake = FakeAuthApi()
        fake.result = Result.failure(AuthRejectedException())
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        val message = "Sign in failed. Check your details and try again."
        composeTestRule.onNodeWithText(message).performScrollTo()
        composeTestRule.onNodeWithText(message).assertIsDisplayed()
        composeTestRule
            .onNode(SemanticsMatcher.expectValue(SemanticsProperties.Error, message))
            .assertExists()
    }

    @Test
    fun unreachableLogin_errorCard_isDisplayed() {
        val fake = FakeAuthApi()
        fake.result = Result.failure(IOException("connection refused"))
        setEntryContent(fake)
        fillValidForm()
        composeTestRule.onNodeWithText("Continue").performScrollTo()
        composeTestRule.onNodeWithText("Continue").performClick()

        composeTestRule
            .onNodeWithText("Cannot reach the server. Check the address and try again.")
            .performScrollTo()
        composeTestRule
            .onNodeWithText("Cannot reach the server. Check the address and try again.")
            .assertIsDisplayed()
    }
}
