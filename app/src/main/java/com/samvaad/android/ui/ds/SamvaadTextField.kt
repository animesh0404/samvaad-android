package com.samvaad.android.ui.ds

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.error
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.VisualTransformation

/**
 * Samvaad text field (Slice A).
 *
 * Thin wrapper over Material 3 [OutlinedTextField]: no custom drawing,
 * no state ownership. Error/supporting text renders below the field in
 * tokenized roles; the error string is also exposed through error
 * semantics so screen readers announce it.
 */
@Composable
fun SamvaadTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    singleLine: Boolean = true,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    trailingContent: (@Composable () -> Unit)? = null,
    supportingText: String? = null,
    errorText: String? = null,
) {
    val error = errorText
    Column(modifier = modifier.fillMaxWidth()) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text(label) },
            enabled = enabled,
            singleLine = singleLine,
            keyboardOptions = keyboardOptions,
            keyboardActions = keyboardActions,
            visualTransformation = visualTransformation,
            trailingIcon = trailingContent,
            isError = error != null,
            supportingText = {
                when {
                    error != null -> Text(error)
                    supportingText != null -> Text(supportingText)
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .semantics { if (error != null) error(error) },
        )
    }
}
