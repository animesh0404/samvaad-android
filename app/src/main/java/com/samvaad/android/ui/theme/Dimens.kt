package com.samvaad.android.ui.theme

import androidx.compose.ui.unit.dp

/**
 * Samvaad spacing and dimension tokens (Slice A).
 *
 * Call sites use these instead of hardcoded dp values.
 */
object SamvaadSpacing {
    val XSmall = 4.dp
    val Small = 8.dp
    val Medium = 12.dp
    val Large = 16.dp
    val XLarge = 24.dp
    val XXLarge = 32.dp
}

object SamvaadDimens {
    /** Minimum touch target for interactive elements. */
    val MinTouchTarget = 48.dp

    /** Maximum content width for single-column entry/form screens. */
    val MaxContentWidth = 480.dp

    /** Brand mark size on the entry screen. */
    val BrandMarkSize = 96.dp

    /** Primary action minimum height. */
    val ActionMinHeight = 52.dp

    /** Standard progress-indicator size for status blocks. */
    val StatusIndicatorSize = 32.dp
}
