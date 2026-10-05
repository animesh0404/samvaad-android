package com.samvaad.android

import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.samvaad.android.friends.FriendEntry
import com.samvaad.android.friends.FriendRequestRecord

/**
 * Friends renderer (Slice 14: add friend + incoming requests + roster).
 *
 * Pure presentation like [ComposerUi]: all state lives in HomeScreen,
 * this file only renders. Server usernames are display strings; tokens
 * never reach here.
 */
@Composable
fun FriendsSection(
    friends: List<FriendEntry>?,
    incoming: List<FriendRequestRecord>?,
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
) {
    Text(text = "Friends", style = MaterialTheme.typography.titleMedium)
    OutlinedTextField(
        value = addUsername,
        onValueChange = onAddUsernameChange,
        // Distinct from the composer "Friend username": both render on
        // the same screen once messaging is available.
        label = { Text("New friend username") },
        singleLine = true,
    )
    Button(
        onClick = onSendRequest,
        enabled = !sendingRequest && addUsername.isNotBlank(),
    ) {
        Text(if (sendingRequest) "Sending…" else "Add friend")
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
    if (loadingRoster) {
        CircularProgressIndicator(modifier = Modifier.size(32.dp))
    } else {
        val roster = friends
        if (roster == null) {
            TextButton(onClick = onRefreshRoster) {
                Text("Refresh friends")
            }
        } else if (roster.isEmpty()) {
            Text(
                text = "No friends yet. Add someone above.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        } else {
            roster.forEach { friend ->
                Text(
                    text = friend.username,
                    style = MaterialTheme.typography.bodyMedium
                )
            }
        }
        val pending = incoming
        if (pending != null && pending.isNotEmpty()) {
            Text(
                text = "Friend requests",
                style = MaterialTheme.typography.titleSmall
            )
            pending.forEach { request ->
                Text(
                    text = "Request from ${request.senderUsername}",
                    style = MaterialTheme.typography.bodyMedium
                )
                val busy = respondingRequestId != null
                Button(
                    onClick = { onAccept(request.requestId) },
                    enabled = !busy,
                ) {
                    Text(
                        if (respondingRequestId == request.requestId) {
                            "Accepting…"
                        } else {
                            "Accept"
                        }
                    )
                }
                Button(
                    onClick = { onReject(request.requestId) },
                    enabled = !busy,
                ) {
                    Text("Reject")
                }
            }
        }
        if (rosterError != null) {
            Text(
                text = rosterError,
                color = MaterialTheme.colorScheme.error
            )
        }
        if (respondError != null) {
            Text(
                text = respondError,
                color = MaterialTheme.colorScheme.error
            )
        }
        TextButton(onClick = onRefreshRoster) {
            Text("Refresh friends")
        }
    }
}
