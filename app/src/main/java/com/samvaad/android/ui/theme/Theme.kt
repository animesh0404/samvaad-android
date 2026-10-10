package com.samvaad.android.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.platform.LocalContext

private val SamvaadLightColorScheme = lightColorScheme(
    primary = SamvaadTealPrimaryLight,
    onPrimary = SamvaadTealOnPrimaryLight,
    primaryContainer = SamvaadTealPrimaryContainerLight,
    onPrimaryContainer = SamvaadTealOnPrimaryContainerLight,
    secondary = SamvaadSageSecondaryLight,
    onSecondary = SamvaadSageOnSecondaryLight,
    secondaryContainer = SamvaadSageSecondaryContainerLight,
    onSecondaryContainer = SamvaadSageOnSecondaryContainerLight,
    tertiary = SamvaadAmberTertiaryLight,
    onTertiary = SamvaadAmberOnTertiaryLight,
    tertiaryContainer = SamvaadAmberTertiaryContainerLight,
    onTertiaryContainer = SamvaadAmberOnTertiaryContainerLight,
    background = SamvaadBackgroundLight,
    onBackground = SamvaadOnBackgroundLight,
    surface = SamvaadSurfaceLight,
    onSurface = SamvaadOnSurfaceLight,
    surfaceVariant = SamvaadSurfaceVariantLight,
    onSurfaceVariant = SamvaadOnSurfaceVariantLight,
    surfaceContainerLow = SamvaadSurfaceContainerLowLight,
    surfaceContainer = SamvaadSurfaceContainerLight,
    surfaceContainerHigh = SamvaadSurfaceContainerHighLight,
    surfaceContainerHighest = SamvaadSurfaceContainerHighestLight,
    outline = SamvaadOutlineLight,
)

private val SamvaadDarkColorScheme = darkColorScheme(
    primary = SamvaadTealPrimaryDark,
    onPrimary = SamvaadTealOnPrimaryDark,
    primaryContainer = SamvaadTealPrimaryContainerDark,
    onPrimaryContainer = SamvaadTealOnPrimaryContainerDark,
    secondary = SamvaadSageSecondaryDark,
    onSecondary = SamvaadSageOnSecondaryDark,
    secondaryContainer = SamvaadSageSecondaryContainerDark,
    onSecondaryContainer = SamvaadSageOnSecondaryContainerDark,
    tertiary = SamvaadAmberTertiaryDark,
    onTertiary = SamvaadAmberOnTertiaryDark,
    tertiaryContainer = SamvaadAmberTertiaryContainerDark,
    onTertiaryContainer = SamvaadAmberOnTertiaryContainerDark,
    background = SamvaadBackgroundDark,
    onBackground = SamvaadOnBackgroundDark,
    surface = SamvaadSurfaceDark,
    onSurface = SamvaadOnSurfaceDark,
    surfaceVariant = SamvaadSurfaceVariantDark,
    onSurfaceVariant = SamvaadOnSurfaceVariantDark,
    surfaceContainerLow = SamvaadSurfaceContainerLowDark,
    surfaceContainer = SamvaadSurfaceContainerDark,
    surfaceContainerHigh = SamvaadSurfaceContainerHighDark,
    surfaceContainerHighest = SamvaadSurfaceContainerHighestDark,
    outline = SamvaadOutlineDark,
)

/**
 * Samvaad product decision (Slice B): the semantic brand palette is
 * authoritative. Dynamic color stays implemented behind [dynamicColor]
 * so it can be reintroduced if product requirements change, but it is
 * no longer the default.
 */
@Composable
fun SamvaadTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    // Dynamic color is available on Android 12+
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> SamvaadDarkColorScheme
        else -> SamvaadLightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        shapes = SamvaadShapes,
        content = content
    )
}