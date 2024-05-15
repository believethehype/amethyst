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
package com.vitorpamplona.amethyst.ui.screen.loggedIn

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Modifier
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vitorpamplona.amethyst.model.LocalCache
import com.vitorpamplona.amethyst.service.relays.Client
import com.vitorpamplona.amethyst.ui.screen.FeedEmptywithStatus
import com.vitorpamplona.amethyst.ui.screen.NostrNIP90ContentDiscoveryFeedViewModel
import com.vitorpamplona.amethyst.ui.screen.NostrNIP90StatusFeedViewModel
import com.vitorpamplona.amethyst.ui.screen.RefresheableBox
import com.vitorpamplona.amethyst.ui.screen.RenderFeedState
import com.vitorpamplona.amethyst.ui.screen.SaveableFeedState
import com.vitorpamplona.quartz.events.AppDefinitionEvent
import com.vitorpamplona.quartz.events.NIP90ContentDiscoveryRequestEvent

@Composable
fun NIP90ContentDiscoveryScreen(
    DVMID: String,
    accountViewModel: AccountViewModel,
    nav: (String) -> Unit,
) {
    var requestID = ""
    val thread =
        Thread {
            try {
                NIP90ContentDiscoveryRequestEvent.create(DVMID, accountViewModel.account.signer) {
                    Client.send(it)
                    requestID = it.id
                    LocalCache.justConsume(it, null)
                }
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }

    thread.start()
    thread.join()

    val resultFeedViewModel: NostrNIP90ContentDiscoveryFeedViewModel =
        viewModel(
            key = "NostrNIP90ContentDiscoveryFeedViewModel",
            factory = NostrNIP90ContentDiscoveryFeedViewModel.Factory(accountViewModel.account, dvmkey = DVMID, requestid = requestID),
        )

    val statusFeedViewModel: NostrNIP90StatusFeedViewModel =
        viewModel(
            key = "NostrNIP90StatusFeedViewModel",
            factory = NostrNIP90StatusFeedViewModel.Factory(accountViewModel.account, dvmkey = DVMID, requestid = requestID),
        )

    val userState by accountViewModel.account.decryptBookmarks.observeAsState() // TODO

    LaunchedEffect(userState) {
        resultFeedViewModel.invalidateData()
    }

    RenderNostrNIP90ContentDiscoveryScreen(DVMID, accountViewModel, nav, resultFeedViewModel, statusFeedViewModel)
}

@Composable
@OptIn(ExperimentalFoundationApi::class)
fun RenderNostrNIP90ContentDiscoveryScreen(
    DVMID: String?,
    accountViewModel: AccountViewModel,
    nav: (String) -> Unit,
    resultFeedViewModel: NostrNIP90ContentDiscoveryFeedViewModel,
    statusFeedViewModel: NostrNIP90StatusFeedViewModel,
) {
    Column(Modifier.fillMaxHeight()) {
        val pagerState = rememberPagerState { 2 }
        val coroutineScope = rememberCoroutineScope()
        // TODO 1 Render a nice header with image and DVM name from the id
        // TODO How do we get the event information here?

        var dvminfo = "DVM " + DVMID
        if (DVMID != null) {
            val thread =
                Thread {
                    try {
                        var note = LocalCache.checkGetOrCreateNote(DVMID)
                        if (note != null) {
                            dvminfo = ((note.event as AppDefinitionEvent).appMetaData()?.name ?: "DVM from note")
                        } else {
                            dvminfo = "DVM from not found"
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                    }
                }

            thread.start()
            thread.join()
        }

        // TODO 2 Get the latest event from the statusFeedViewModel
        // TODO How do we extract the latest event.content (or event.status) from statusFeedViewModel
        var dvmStatus = "DVM is processing..."

      /*  if (statusFeedViewModel.localFilter.feed().isNotEmpty()) {
            statusFeedViewModel.localFilter.feed()[0].event?.let { Text(text = it.content()) }
        } else {
            Text(text = "Nah")
        }

         DVMStatusView(
            statusFeedViewModel,
            null,
            enablePullRefresh = false,
            accountViewModel = accountViewModel,
            nav = nav,
        )*/

        // Text(text = dvminfo)

        HorizontalPager(state = pagerState) {
            RefresheableBox(resultFeedViewModel, false) {
                SaveableFeedState(resultFeedViewModel, null) { listState ->
                    RenderFeedState(
                        resultFeedViewModel,
                        accountViewModel,
                        listState,
                        nav,
                        null,
                        onEmpty = {
                            FeedEmptywithStatus(status = dvmStatus) {
                            }
                        },
                    )
                }
            }
        }
    }
}
