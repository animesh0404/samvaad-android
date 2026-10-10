package com.samvaad.android.ui.util

import java.time.LocalDate
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/**
 * Server-timestamp formatting (Slice A).
 *
 * The app stores server timestamps as opaque ISO strings (e.g.
 * `"2026-10-03T10:00:00"`, without an offset, or `""` when absent).
 * This utility only *presents* them; persistence and server semantics
 * are untouched.
 *
 * - null/blank → `""` (caller hides the slot);
 * - unparseable → the trimmed raw string (never lose information);
 * - today → `"21:34"`; yesterday → `"Yesterday"`;
 * - same year → `"03 Oct"`; other years → `"03 Oct 2025"`.
 *
 * [locale] defaults to the device locale at each call (never cached in a
 * static formatter, so a JVM-wide locale change cannot leak across calls).
 */
fun formatServerTimestamp(
    raw: String?,
    nowMillis: Long = System.currentTimeMillis(),
    zone: ZoneId = ZoneId.systemDefault(),
    locale: Locale = Locale.getDefault(),
): String {
    if (raw.isNullOrBlank()) return ""
    val trimmed = raw.trim()
    val parsed = parseServerTimestamp(trimmed, zone) ?: return trimmed
    val today = LocalDate.ofInstant(
        java.time.Instant.ofEpochMilli(nowMillis),
        zone,
    )
    val sameYear = DateTimeFormatter.ofPattern("dd MMM", locale)
    val otherYear = DateTimeFormatter.ofPattern("dd MMM yyyy", locale)
    val time = DateTimeFormatter.ofPattern("HH:mm", locale)
    return when (parsed.toLocalDate()) {
        today -> parsed.format(time)
        today.minusDays(1) -> "Yesterday"
        else -> if (parsed.year == today.year) {
            parsed.format(sameYear)
        } else {
            parsed.format(otherYear)
        }
    }
}

private fun parseServerTimestamp(raw: String, zone: ZoneId): LocalDateTime? {
    parseOffset(raw, zone)?.let { return it }
    return try {
        LocalDateTime.parse(raw, DateTimeFormatter.ISO_LOCAL_DATE_TIME)
    } catch (_: Exception) {
        try {
            LocalDate.parse(raw, DateTimeFormatter.ISO_LOCAL_DATE)
                .atStartOfDay()
        } catch (_: Exception) {
            null
        }
    }
}

private fun parseOffset(raw: String, zone: ZoneId): LocalDateTime? = try {
    OffsetDateTime.parse(raw, DateTimeFormatter.ISO_OFFSET_DATE_TIME)
        .atZoneSameInstant(zone)
        .toLocalDateTime()
} catch (_: Exception) {
    null
}

/**
 * Day-separator label for a raw server timestamp (Slice E).
 *
 * Same parsing rules as [formatServerTimestamp] (blank/unparseable →
 * null: the message joins the surrounding group instead of forcing a
 * bogus separator), but day-granular and always year-qualified outside
 * today/yesterday so separators stay unambiguous: `"Today"`,
 * `"Yesterday"`, else `"03 Oct 2026"`. Presentation only.
 */
fun messageDayLabel(
    raw: String?,
    nowMillis: Long = System.currentTimeMillis(),
    zone: ZoneId = ZoneId.systemDefault(),
    locale: Locale = Locale.getDefault(),
): String? {
    if (raw.isNullOrBlank()) return null
    val parsed = parseServerTimestamp(raw.trim(), zone) ?: return null
    val today = LocalDate.ofInstant(
        java.time.Instant.ofEpochMilli(nowMillis),
        zone,
    )
    return when (parsed.toLocalDate()) {
        today -> "Today"
        today.minusDays(1) -> "Yesterday"
        else -> parsed.format(DateTimeFormatter.ofPattern("dd MMM yyyy", locale))
    }
}
