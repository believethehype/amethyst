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
package com.vitorpamplona.amethyst.ui.note.elements

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.vitorpamplona.amethyst.R
import com.vitorpamplona.amethyst.model.Account
import com.vitorpamplona.amethyst.model.ThemeType
import com.vitorpamplona.amethyst.ui.actions.relays.AddDMRelayListDialog
import com.vitorpamplona.amethyst.ui.note.LoadAddressableNote
import com.vitorpamplona.amethyst.ui.screen.SharedPreferencesViewModel
import com.vitorpamplona.amethyst.ui.screen.loggedIn.AccountViewModel
import com.vitorpamplona.amethyst.ui.theme.BigPadding
import com.vitorpamplona.amethyst.ui.theme.StdPadding
import com.vitorpamplona.amethyst.ui.theme.StdVertSpacer
import com.vitorpamplona.amethyst.ui.theme.ThemeComparisonColumn
import com.vitorpamplona.amethyst.ui.theme.imageModifier
import com.vitorpamplona.quartz.crypto.KeyPair
import com.vitorpamplona.quartz.encoders.HexKey
import com.vitorpamplona.quartz.events.ChatMessageRelayListEvent
import fr.acinq.secp256k1.Hex
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob

@Preview
@Composable
fun AddInboxRelayForDMCardPreview() {
    val sharedPreferencesViewModel: SharedPreferencesViewModel = viewModel()
    val myCoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    sharedPreferencesViewModel.init()
    sharedPreferencesViewModel.updateTheme(ThemeType.DARK)

    val pubkey = "989c3734c46abac7ce3ce229971581a5a6ee39cdd6aa7261a55823fa7f8c4799"

    val myAccount =
        Account(
            keyPair =
                KeyPair(
                    privKey = Hex.decode("0f761f8a5a481e26f06605a1d9b3e9eba7a107d351f43c43a57469b788274499"),
                    pubKey = Hex.decode(pubkey),
                    forcePubKeyCheck = false,
                ),
            scope = myCoroutineScope,
        )

    val accountViewModel =
        AccountViewModel(
            myAccount,
            sharedPreferencesViewModel.sharedPrefs,
        )

    ThemeComparisonColumn {
        AddInboxRelayForDMCard(
            accountViewModel = accountViewModel,
            nav = {},
        )
    }
}

@Composable
fun ObserveRelayListForDMsAndDisplayIfNotFound(
    accountViewModel: AccountViewModel,
    nav: (String) -> Unit,
) {
    ObserveRelayListForDMs(
        accountViewModel = accountViewModel,
    ) { relayListEvent ->
        if (relayListEvent == null) {
            AddInboxRelayForDMCard(
                accountViewModel = accountViewModel,
                nav = nav,
            )
        }
    }
}

@Composable
fun ObserveRelayListForDMs(
    accountViewModel: AccountViewModel,
    inner: @Composable (relayListEvent: ChatMessageRelayListEvent?) -> Unit,
) {
    ObserveRelayListForDMs(
        pubkey = accountViewModel.account.userProfile().pubkeyHex,
        accountViewModel = accountViewModel,
    ) { relayListEvent ->
        inner(relayListEvent)
    }
}

@Composable
fun ObserveRelayListForDMs(
    pubkey: HexKey,
    accountViewModel: AccountViewModel,
    inner: @Composable (relayListEvent: ChatMessageRelayListEvent?) -> Unit,
) {
    LoadAddressableNote(
        ChatMessageRelayListEvent.createAddressTag(pubkey),
        accountViewModel,
    ) { relayList ->
        if (relayList != null) {
            val relayListNoteState by relayList.live().metadata.observeAsState()
            val relayListEvent = relayListNoteState?.note?.event as? ChatMessageRelayListEvent

            inner(relayListEvent)
        }
    }
}

@Composable
fun AddInboxRelayForDMCard(
    accountViewModel: AccountViewModel,
    nav: (String) -> Unit,
) {
    Column(modifier = StdPadding) {
        Card(
            modifier = MaterialTheme.colorScheme.imageModifier,
        ) {
            Column(
                modifier = BigPadding,
            ) {
                // Title
                Text(
                    text = stringResource(id = R.string.dm_relays_not_found),
                    style =
                        TextStyle(
                            fontSize = 20.sp,
                            fontWeight = FontWeight.Bold,
                        ),
                )

                Spacer(modifier = StdVertSpacer)

                Text(
                    text = stringResource(id = R.string.dm_relays_not_found_description),
                )

                Spacer(modifier = StdVertSpacer)

                Text(
                    text = stringResource(id = R.string.dm_relays_not_found_examples),
                )

                Spacer(modifier = StdVertSpacer)

                var wantsToEditRelays by remember { mutableStateOf(false) }
                if (wantsToEditRelays) {
                    AddDMRelayListDialog({ wantsToEditRelays = false }, accountViewModel, nav = nav)
                }

                Button(
                    onClick = {
                        wantsToEditRelays = true
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(text = stringResource(id = R.string.dm_relays_not_found_create_now))
                }
            }
        }
    }
}
