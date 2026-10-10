package com.samvaad.android

import com.samvaad.android.ui.util.formatServerTimestamp
import java.time.ZoneId
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Slice A timestamp-formatter tests. Pure JVM; fixed zone/now.
 */
class TimestampFormatTest {

    private val utc = ZoneId.of("UTC")
    private val en = Locale.ENGLISH

    /** 2026-10-05T12:00:00Z. */
    private val now = 1_791_201_600_000L

    @Test
    fun missing_returnsEmpty() {
        assertEquals("", formatServerTimestamp(null, now, utc, en))
        assertEquals("", formatServerTimestamp("", now, utc, en))
        assertEquals("", formatServerTimestamp("   ", now, utc, en))
    }

    @Test
    fun unparseable_returnsRaw() {
        assertEquals("not-a-time", formatServerTimestamp("not-a-time", now, utc, en))
    }

    @Test
    fun today_returnsTime() {
        assertEquals(
            "09:15",
            formatServerTimestamp("2026-10-05T09:15:00", now, utc, en),
        )
    }

    @Test
    fun yesterday_returnsYesterday() {
        assertEquals(
            "Yesterday",
            formatServerTimestamp("2026-10-04T23:59:00", now, utc, en),
        )
    }

    @Test
    fun olderSameYear_returnsDayMonth() {
        assertEquals(
            "01 Sep",
            formatServerTimestamp("2026-09-01T10:00:00", now, utc, en),
        )
    }

    @Test
    fun otherYear_includesYear() {
        assertEquals(
            "31 Dec 2025",
            formatServerTimestamp("2025-12-31T10:00:00", now, utc, en),
        )
    }

    @Test
    fun offsetInput_isConvertedToZone() {
        assertEquals(
            "07:15",
            formatServerTimestamp("2026-10-05T09:15:00+02:00", now, utc, en),
        )
    }
}
