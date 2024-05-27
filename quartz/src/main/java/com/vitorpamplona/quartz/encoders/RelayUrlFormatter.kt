/**
 * Copyright (c) 2024 Vitor Pamplona
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
package com.vitorpamplona.quartz.encoders

class RelayUrlFormatter {
    companion object {
        fun displayUrl(url: String): String {
            return url.trim().removePrefix("wss://").removePrefix("ws://").removeSuffix("/")
        }

        fun normalize(url: String): String {
            var newUrl =
                if (!url.startsWith("wss://") && !url.startsWith("ws://")) {
                    if (url.endsWith(".onion") || url.endsWith(".onion/")) {
                        "ws://$url"
                    } else {
                        "wss://$url"
                    }
                } else {
                    url
                }

            if (url.endsWith("/")) newUrl = newUrl.dropLast(1)

            return newUrl
        }

        fun getHttpsUrl(dirtyUrl: String): String {
            return if (dirtyUrl.contains("://")) {
                dirtyUrl.replace("wss://", "https://").replace("ws://", "http://")
            } else {
                "https://$dirtyUrl"
            }
        }
    }
}
