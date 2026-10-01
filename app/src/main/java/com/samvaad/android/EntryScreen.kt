package com.samvaad.android

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.samvaad.android.ui.theme.SamvaadTheme

/**
 * First Samvaad entry screen (Slice 1).
 *
 * Local UI state only: the entered server address and username are held in
 * Compose [remember] state. Continue only flips local state to show a
 * confirmation. No networking, authentication, persistence, or navigation.
 */
@Composable
fun SamvaadEntryScreen() {
    var serverAddress by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var continued by remember { mutableStateOf(false) }

    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text(
                text = "Samvaad",
                style = MaterialTheme.typography.headlineMedium
            )
            OutlinedTextField(
                value = serverAddress,
                onValueChange = {
                    serverAddress = it
                    continued = false
                },
                label = { Text("Server address") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            OutlinedTextField(
                value = username,
                onValueChange = {
                    username = it
                    continued = false
                },
                label = { Text("Username") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth()
            )
            Button(onClick = { continued = true }) {
                Text("Continue")
            }
            if (continued) {
                Text(text = "Continuing as $username on $serverAddress")
            }
        }
    }
}

@Preview(showBackground = true)
@Composable
fun SamvaadEntryScreenPreview() {
    SamvaadTheme {
        SamvaadEntryScreen()
    }
}
