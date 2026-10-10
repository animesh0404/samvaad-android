package com.samvaad.android.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

/**
 * Samvaad shape scale (Slice A).
 *
 * Three steps only. Screens must not invent per-screen corner radii;
 * bubble/message-specific asymmetry arrives with the conversation slice.
 */
val SamvaadShapes = Shapes(
    small = RoundedCornerShape(8.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(24.dp),
)
