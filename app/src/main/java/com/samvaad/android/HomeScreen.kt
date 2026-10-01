package com.samvaad.android

import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.samvaad.android.ui.theme.SamvaadTheme

/**
 * Placeholder authenticated surface.
 *
 * Shows only the authenticated identifier. Receives no tokens: the
 * in-memory [AuthSession] stays with the caller. Device enrollment and
 * messaging do not exist yet and are not implied.
 */
@Composable
fun HomeScreen(identifier: String) {
    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Image(
                painter = painterResource(R.drawable.samvaad_logo),
                contentDescription = "Samvaad logo",
                modifier = Modifier.size(96.dp)
            )
            Text(
                text = "Samvaad",
                style = MaterialTheme.typography.headlineMedium
            )
            Text(text = "Signed in as $identifier")
            Text(
                text = "Device setup will continue here.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun HomeScreenPreview() {
    SamvaadTheme {
        HomeScreen(identifier = "alice")
    }
}
