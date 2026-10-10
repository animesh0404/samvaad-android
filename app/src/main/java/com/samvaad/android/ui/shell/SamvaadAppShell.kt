package com.samvaad.android.ui.shell

import androidx.compose.animation.togetherWith
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.consumeWindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.navigation3.runtime.entryProvider
import androidx.navigation3.runtime.rememberNavBackStack
import androidx.navigation3.ui.NavDisplay
import com.samvaad.android.AuthApi
import com.samvaad.android.AuthSession
import com.samvaad.android.HomeScreen
import com.samvaad.android.HttpAuthApi
import com.samvaad.android.crypto.WrappingKeyProvider
import com.samvaad.android.enroll.AdoptedDevice
import com.samvaad.android.enroll.E2eeDeviceApi
import com.samvaad.android.enroll.EnrollmentCoordinator
import com.samvaad.android.friends.FriendsApi
import com.samvaad.android.session.RealtimeInbox
import com.samvaad.android.session.SessionStore
import com.samvaad.android.ui.ds.StatusCard
import com.samvaad.android.ui.ds.StatusKind
import com.samvaad.android.ui.navigation.AppDestination
import com.samvaad.android.ui.navigation.HomeSection
import com.samvaad.android.ui.theme.SamvaadDimens
import com.samvaad.android.ui.theme.SamvaadSpacing

/**
 * Authenticated application shell (Slice B).
 *
 * Owns WHERE the user is (Navigation 3 back stack, bottom bar, top bar).
 * Existing feature logic owns WHAT each destination does: entries render
 * [HomeScreen] section slices with external navigation callbacks, so the
 * enrollment/messaging/friends lifecycles stay exactly where they were.
 *
 * Each destination mounts its own HomeScreen, so per-destination state
 * (messaging graph, realtime socket, initial loads, one session-bind
 * proof) is scoped to the visible destination and torn down on leave:
 * no duplicate collectors or subscriptions can outlive their screen.
 * Hoisting shared scope above NavDisplay is deferred to a later slice.
 */
@Composable
fun SamvaadAppShell(
    identifier: String,
    session: AuthSession,
    serverAddress: String,
    coordinator: EnrollmentCoordinator? = null,
    authApi: AuthApi = HttpAuthApi(),
    sessionStore: SessionStore? = null,
    deviceApi: E2eeDeviceApi? = null,
    wrappingKeys: WrappingKeyProvider? = null,
    friendsApi: FriendsApi? = null,
    onLogout: () -> Unit = {},
    realtimeSocketFactory: ((
        java.net.URI,
        RealtimeInbox.SocketEvents,
    ) -> RealtimeInbox.RealtimeSocket)? = null,
) {
    val backStack = rememberNavBackStack(AppDestination.Chats)
    val current = (backStack.lastOrNull() as? AppDestination) ?: AppDestination.Chats
    val topTab = when (current) {
        AppDestination.Chats -> AppDestination.Chats
        is AppDestination.ChatDetail -> AppDestination.Chats
        AppDestination.Friends -> AppDestination.Friends
        AppDestination.Settings -> AppDestination.Settings
    }
    val isDetail = current is AppDestination.ChatDetail

    fun selectTab(tab: AppDestination) {
        if (topTab == tab) return
        backStack.clear()
        backStack.add(tab)
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            SamvaadShellTopBar(
                isDetail = isDetail,
                onBack = { backStack.removeLastOrNull() },
            )
        },
        bottomBar = {
            // Full-screen conversation: no bottom bar (adaptive two-pane
            // deactivates this in a later slice).
            if (!isDetail) {
                // Inline lambda (not a bound `::selectTab` reference):
                // bound references to local functions can go stale
                // across recompositions and silently drop navigations.
                SamvaadBottomBar(
                    selected = topTab,
                    onSelect = { selectTab(it) },
                )
            }
        },
    ) { innerPadding ->
        NavDisplay(
            backStack = backStack,
            onBack = { backStack.removeLastOrNull() },
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .consumeWindowInsets(innerPadding),
            entryProvider = entryProvider {
                entry<AppDestination.Chats> {
                    HomeScreen(
                        identifier = identifier,
                        session = session,
                        serverAddress = serverAddress,
                        coordinator = coordinator,
                        authApi = authApi,
                        sessionStore = sessionStore,
                        deviceApi = deviceApi,
                        wrappingKeys = wrappingKeys,
                        friendsApi = friendsApi,
                        onLogout = onLogout,
                        realtimeSocketFactory = realtimeSocketFactory,
                        section = HomeSection.Chats,
                        externalNav = true,
                        onOpenConversation = { id ->
                            backStack.add(AppDestination.ChatDetail(id))
                        },
                    )
                }
                entry<AppDestination.Friends> {
                    HomeScreen(
                        identifier = identifier,
                        session = session,
                        serverAddress = serverAddress,
                        coordinator = coordinator,
                        authApi = authApi,
                        sessionStore = sessionStore,
                        deviceApi = deviceApi,
                        wrappingKeys = wrappingKeys,
                        friendsApi = friendsApi,
                        onLogout = onLogout,
                        realtimeSocketFactory = realtimeSocketFactory,
                        section = HomeSection.Friends,
                        externalNav = true,
                        // Slice D: the accepted-friend Message CTA resolves
                        // to the existing ChatDetail route (same as Chats).
                        onOpenConversation = { id ->
                            backStack.add(AppDestination.ChatDetail(id))
                        },
                    )
                }
                entry<AppDestination.Settings> {
                    HomeScreen(
                        identifier = identifier,
                        session = session,
                        serverAddress = serverAddress,
                        coordinator = coordinator,
                        authApi = authApi,
                        sessionStore = sessionStore,
                        deviceApi = deviceApi,
                        wrappingKeys = wrappingKeys,
                        friendsApi = friendsApi,
                        onLogout = onLogout,
                        realtimeSocketFactory = realtimeSocketFactory,
                        section = HomeSection.Settings,
                        externalNav = true,
                    )
                }
                entry<AppDestination.ChatDetail> { detail ->
                    HomeScreen(
                        identifier = identifier,
                        session = session,
                        serverAddress = serverAddress,
                        coordinator = coordinator,
                        authApi = authApi,
                        sessionStore = sessionStore,
                        deviceApi = deviceApi,
                        wrappingKeys = wrappingKeys,
                        friendsApi = friendsApi,
                        onLogout = onLogout,
                        realtimeSocketFactory = realtimeSocketFactory,
                        section = HomeSection.Detail,
                        detailConversationId = detail.conversationId,
                        externalNav = true,
                        onOpenConversation = { id ->
                            backStack.add(AppDestination.ChatDetail(id))
                        },
                        onCloseConversation = { backStack.removeLastOrNull() },
                    )
                }
            },
        )
    }
}

private val TopTabs = listOf(
    AppDestination.Chats,
    AppDestination.Friends,
    AppDestination.Settings,
)

private fun tabLabel(tab: AppDestination): String = when (tab) {
    AppDestination.Chats -> "Chats"
    AppDestination.Friends -> "Friends"
    AppDestination.Settings -> "Settings"
    is AppDestination.ChatDetail -> "Chats"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SamvaadShellTopBar(
    isDetail: Boolean,
    onBack: () -> Unit,
) {
    TopAppBar(
        title = { Text(if (isDetail) "Chat" else "Samvaad") },
        navigationIcon = {
            if (isDetail) {
                TextButton(
                    onClick = onBack,
                    // Slice G: back meets the 48dp touch target.
                    modifier = Modifier.heightIn(
                        min = SamvaadDimens.MinTouchTarget,
                    ),
                ) {
                    Text("Back")
                }
            }
        },
    )
}

/**
 * Primary navigation. Text treatment is temporary: no icon dependency
 * exists in this project and this slice adds none (Slice A rule).
 * Selected state comes from NavigationBarItem semantics, not visuals.
 */
@Composable
private fun SamvaadBottomBar(
    selected: AppDestination,
    onSelect: (AppDestination) -> Unit,
) {
    NavigationBar {
        TopTabs.forEach { tab ->
            val label = tabLabel(tab)
            NavigationBarItem(
                selected = selected == tab,
                onClick = { onSelect(tab) },
                icon = {
                    Text(
                        text = label.take(1),
                        style = MaterialTheme.typography.labelLarge,
                    )
                },
                modifier = Modifier.testTag("tab-$label"),
                label = { Text(label) },
            )
        }
    }
}

/**
 * Settings destination content (Slice F).
 *
 * Real state only, rendered from the authenticated session and the
 * adopted device record the caller already owns: account identity,
 * device role/status/readiness, and the existing guarded logout flow.
 * Nothing here is configurable — there are no app preferences with
 * real behavior behind them, so no toggles are invented. Device setup,
 * approval, and recovery actions stay in their existing enrollment
 * surfaces; this screen reports device state without duplicating them.
 * No private keys, recovery secrets, or cryptographic material are
 * rendered (the adopted record itself never holds them).
 */
@Composable
fun SettingsSection(
    identifier: String,
    serverAddress: String,
    adopted: AdoptedDevice?,
    onLogout: () -> Unit,
) {
    // Own scroll: the host screen skips its outer scroll for sectioned
    // destinations, so this column scrolls itself (single scroller, no
    // nesting). Short content, but font scaling can still overflow it.
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(vertical = SamvaadSpacing.Large)
            .testTag("SettingsList"),
        verticalArrangement = Arrangement.spacedBy(SamvaadSpacing.Large),
    ) {
        Text(
            text = "Settings",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
        )
        SettingsHeader(text = "Account")
        SettingsRow(label = "Username", value = identifier)
        SettingsRow(label = "Server", value = serverAddress)
        SettingsHeader(text = "Device")
        val device = adopted
        if (device == null) {
            StatusCard(
                kind = StatusKind.Info,
                message = "This device is not set up yet.",
                modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
            )
        } else {
            SettingsRow(label = "Role", value = device.roleHint)
            SettingsRow(label = "Status", value = device.statusHint)
            SettingsRow(
                label = "Signal device",
                value = "#${device.signalDeviceId}",
            )
            if (device.hasLocalKeys) {
                SettingsRow(label = "Messaging", value = "Ready")
            } else {
                SettingsRow(label = "Messaging", value = "Limited")
                StatusCard(
                    kind = StatusKind.Warning,
                    message = "This installation holds no private " +
                        "messaging keys, so messaging is unavailable " +
                        "here. To enable messaging here, recover as a " +
                        "new device.",
                    modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
                )
            }
            if (!device.codesAcknowledged) {
                StatusCard(
                    kind = StatusKind.Warning,
                    message = "Recovery codes were not confirmed. " +
                        "A future update will let you rotate them.",
                    modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
                )
            }
        }
        SettingsHeader(text = "Session")
        Button(
            // Inline lambda, not a bound reference (Slice B finding).
            onClick = { onLogout() },
            colors = ButtonDefaults.buttonColors(
                containerColor = MaterialTheme.colorScheme.errorContainer,
                contentColor = MaterialTheme.colorScheme.onErrorContainer,
            ),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = SamvaadSpacing.Large)
                .heightIn(min = SamvaadDimens.ActionMinHeight),
        ) {
            Text("Log out")
        }
    }
}

@Composable
private fun SettingsHeader(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(horizontal = SamvaadSpacing.Large),
    )
}

/**
 * Compact non-interactive settings row: label over value. Merged into
 * one announcement ("Role, PRIMARY") so readers get both at once.
 */
@Composable
private fun SettingsRow(label: String, value: String) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(
                horizontal = SamvaadSpacing.Large,
                vertical = SamvaadSpacing.XSmall,
            )
            .semantics(mergeDescendants = true) {
                contentDescription = "$label, $value"
            },
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyLarge,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
        )
    }
}
