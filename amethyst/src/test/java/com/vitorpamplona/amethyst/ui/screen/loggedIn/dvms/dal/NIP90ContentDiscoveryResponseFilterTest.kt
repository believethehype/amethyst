/*
 * Copyright (c) 2025 Vitor Pamplona
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
 * AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.vitorpamplona.amethyst.ui.screen.loggedIn.dvms.dal

import com.vitorpamplona.amethyst.commons.model.Note
import com.vitorpamplona.amethyst.commons.model.User
import com.vitorpamplona.amethyst.model.Account
import com.vitorpamplona.quartz.nip90Dvms.contentDiscoveryResponse.NIP90ContentDiscoveryResponseEvent
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class NIP90ContentDiscoveryResponseFilterTest {
    private val dvm = "a1".repeat(32)
    private val previousRequest = "a2".repeat(32)
    private val currentRequest = "a3".repeat(32)
    private val filter = NIP90ContentDiscoveryResponseFilter(mockk<Account>(), dvm, listOf(currentRequest, previousRequest))

    @Test
    fun lateResponseAfterRefreshStillPopulatesFeed() {
        val post = "a4".repeat(32)
        val response = response(previousRequest, post, 100)

        assertEquals(listOf(post), filter.applyFilter(setOf(response)).map { it.idHex })
    }

    @Test
    fun subsequentResponseUpdatesTheSelectedResult() {
        filter.applyFilter(setOf(response(previousRequest, "a5".repeat(32), 100)))
        val post = "a6".repeat(32)

        assertEquals(listOf(post), filter.applyFilter(setOf(response(currentRequest, post, 200))).map { it.idHex })
        // An older reply arriving out of order must not roll the selected result back.
        assertEquals(listOf(post), filter.applyFilter(setOf(response(previousRequest, "a7".repeat(32), 150))).map { it.idHex })
    }

    @Test
    fun ignoresUnrelatedRequestsAndOtherDvms() {
        assertFalse(filter.acceptableEvent(response("b1".repeat(32), "b2".repeat(32), 100)))
        assertFalse(filter.acceptableEvent(response(currentRequest, "b3".repeat(32), 100, author = "b4".repeat(32))))
    }

    private fun response(
        request: String,
        post: String,
        createdAt: Long,
        author: String = dvm,
    ): Note {
        val event =
            NIP90ContentDiscoveryResponseEvent(
                id = post,
                pubKey = author,
                createdAt = createdAt,
                tags = arrayOf(arrayOf("e", request)),
                content = """[["e","$post"]]""",
                sig = "",
            )
        return Note(event.id).also { it.loadEvent(event, mockk<User>(), emptyList()) }
    }
}
