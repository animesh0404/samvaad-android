package com.samvaad.android

import com.samvaad.android.enroll.PrekeyIdAllocator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Local ID allocation: monotonic, namespaced, never reused per device. */
class PrekeyIdAllocatorTest {

    @Test
    fun namespaces_areIndependentAndMonotonic() {
        val allocator = PrekeyIdAllocator()
        assertEquals(1, allocator.nextSignedPrekeyId())
        assertEquals(2, allocator.nextSignedPrekeyId())
        assertEquals(1, allocator.nextKyberPrekeyId())
        assertEquals(listOf(1, 2, 3), allocator.nextOneTimePrekeyIds(3))
        assertEquals(listOf(4, 5), allocator.nextOneTimePrekeyIds(2))
    }

    @Test
    fun highWaterMarks_restoreDeterministically() {
        val allocator = PrekeyIdAllocator(signedHighWater = 5, kyberHighWater = 2, otpkHighWater = 100)
        assertEquals(6, allocator.nextSignedPrekeyId())
        assertEquals(3, allocator.nextKyberPrekeyId())
        assertEquals(listOf(101, 102), allocator.nextOneTimePrekeyIds(2))
    }

    @Test
    fun registrationId_inPositiveRange() {
        repeat(50) {
            val id = PrekeyIdAllocator.newRegistrationId()
            assertTrue(id in 1..16383)
        }
    }
}
