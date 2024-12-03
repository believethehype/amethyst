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
package com.vitorpamplona.amethyst.ui.components

import android.util.Log
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.InlineTextContent
import androidx.compose.foundation.text.appendInlineContent
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.adaptive.currentWindowAdaptiveInfo
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.Placeholder
import androidx.compose.ui.text.PlaceholderVerticalAlign
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.core.net.toUri
import coil3.compose.AsyncImage
import coil3.compose.AsyncImagePainter
import coil3.compose.SubcomposeAsyncImage
import coil3.compose.SubcomposeAsyncImageContent
import com.google.accompanist.permissions.ExperimentalPermissionsApi
import com.vitorpamplona.amethyst.Amethyst
import com.vitorpamplona.amethyst.R
import com.vitorpamplona.amethyst.commons.richtext.BaseMediaContent
import com.vitorpamplona.amethyst.commons.richtext.MediaLocalImage
import com.vitorpamplona.amethyst.commons.richtext.MediaLocalVideo
import com.vitorpamplona.amethyst.commons.richtext.MediaPreloadedContent
import com.vitorpamplona.amethyst.commons.richtext.MediaUrlContent
import com.vitorpamplona.amethyst.commons.richtext.MediaUrlImage
import com.vitorpamplona.amethyst.commons.richtext.MediaUrlVideo
import com.vitorpamplona.amethyst.service.Blurhash
import com.vitorpamplona.amethyst.ui.actions.CrossfadeIfEnabled
import com.vitorpamplona.amethyst.ui.actions.InformationDialog
import com.vitorpamplona.amethyst.ui.actions.LoadingAnimation
import com.vitorpamplona.amethyst.ui.components.util.DeviceUtils
import com.vitorpamplona.amethyst.ui.navigation.getActivity
import com.vitorpamplona.amethyst.ui.note.BlankNote
import com.vitorpamplona.amethyst.ui.note.DownloadForOfflineIcon
import com.vitorpamplona.amethyst.ui.note.HashCheckFailedIcon
import com.vitorpamplona.amethyst.ui.note.HashCheckIcon
import com.vitorpamplona.amethyst.ui.screen.loggedIn.AccountViewModel
import com.vitorpamplona.amethyst.ui.stringRes
import com.vitorpamplona.amethyst.ui.theme.Font17SP
import com.vitorpamplona.amethyst.ui.theme.Size20dp
import com.vitorpamplona.amethyst.ui.theme.Size24dp
import com.vitorpamplona.amethyst.ui.theme.Size30dp
import com.vitorpamplona.amethyst.ui.theme.Size75dp
import com.vitorpamplona.amethyst.ui.theme.hashVerifierMark
import com.vitorpamplona.amethyst.ui.theme.imageModifier
import com.vitorpamplona.amethyst.ui.theme.videoGalleryModifier
import com.vitorpamplona.quartz.crypto.CryptoUtils
import com.vitorpamplona.quartz.encoders.toHexKey
import com.vitorpamplona.quartz.events.Dimension
import kotlinx.collections.immutable.ImmutableList
import kotlinx.collections.immutable.persistentListOf
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlin.time.Duration.Companion.seconds

@Composable
fun ZoomableContentView(
    content: BaseMediaContent,
    images: ImmutableList<BaseMediaContent> = remember(content) { persistentListOf(content) },
    roundedCorner: Boolean,
    isFiniteHeight: Boolean,
    accountViewModel: AccountViewModel,
) {
    var dialogOpen by remember(content) { mutableStateOf(false) }

    val activity = LocalView.current.context.getActivity()
    val currentWindowSize = currentWindowAdaptiveInfo().windowSizeClass

    val isLandscapeMode = DeviceUtils.isLandscapeMetric(LocalContext.current)
    val isFoldableOrLarge = DeviceUtils.windowIsLarge(windowSize = currentWindowSize, isInLandscapeMode = isLandscapeMode)
    val isOrientationLocked = DeviceUtils.screenOrientationIsLocked(LocalContext.current)

    val contentScale =
        if (isFiniteHeight) {
            ContentScale.Fit
        } else {
            ContentScale.FillWidth
        }

    when (content) {
        is MediaUrlImage ->
            SensitivityWarning(content.contentWarning != null, accountViewModel) {
                TwoSecondController(content) { controllerVisible ->
                    val mainImageModifier = Modifier.fillMaxWidth().clickable { dialogOpen = true }
                    val loadedImageModifier = if (roundedCorner) MaterialTheme.colorScheme.imageModifier else Modifier.fillMaxWidth()

                    UrlImageView(content, contentScale, mainImageModifier, loadedImageModifier, controllerVisible, accountViewModel = accountViewModel)
                }
            }
        is MediaUrlVideo ->
            SensitivityWarning(content.contentWarning != null, accountViewModel) {
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    VideoView(
                        videoUri = content.url,
                        mimeType = content.mimeType,
                        title = content.description,
                        artworkUri = content.artworkUri,
                        authorName = content.authorName,
                        dimensions = content.dim,
                        blurhash = content.blurhash,
                        roundedCorner = roundedCorner,
                        isFiniteHeight = isFiniteHeight,
                        nostrUriCallback = content.uri,
                        onDialog = {
                            dialogOpen = true
                            // if (!isFoldableOrLarge && !isOrientationLocked) {
                            //    DeviceUtils.changeDeviceOrientation(isLandscapeMode, activity)
                            // }
                        },
                        accountViewModel = accountViewModel,
                    )
                }
            }
        is MediaLocalImage ->
            TwoSecondController(content) { controllerVisible ->
                val mainImageModifier = Modifier.fillMaxWidth().clickable { dialogOpen = true }
                val loadedImageModifier = if (roundedCorner) MaterialTheme.colorScheme.imageModifier else Modifier.fillMaxWidth()

                LocalImageView(content, contentScale, mainImageModifier, loadedImageModifier, controllerVisible, accountViewModel = accountViewModel)
            }
        is MediaLocalVideo ->
            content.localFile?.let {
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    VideoView(
                        videoUri = it.toUri().toString(),
                        mimeType = content.mimeType,
                        title = content.description,
                        artworkUri = content.artworkUri,
                        authorName = content.authorName,
                        roundedCorner = roundedCorner,
                        isFiniteHeight = isFiniteHeight,
                        nostrUriCallback = content.uri,
                        onDialog = { dialogOpen = true },
                        accountViewModel = accountViewModel,
                    )
                }
            }
    }

    if (dialogOpen) {
        ZoomableImageDialog(
            content,
            images,
            onDismiss = {
                dialogOpen = false
                // if (!isFoldableOrLarge && !isOrientationLocked) DeviceUtils.changeDeviceOrientation(isLandscapeMode, activity)
            },
            accountViewModel,
        )
    }
}

@Composable
fun GalleryContentView(
    content: BaseMediaContent,
    roundedCorner: Boolean,
    isFiniteHeight: Boolean,
    accountViewModel: AccountViewModel,
) {
    when (content) {
        is MediaUrlImage ->
            SensitivityWarning(content.contentWarning != null, accountViewModel) {
                TwoSecondController(content) { controllerVisible ->
                    val mainImageModifier = Modifier.fillMaxWidth()
                    val loadedImageModifier = if (roundedCorner) MaterialTheme.colorScheme.imageModifier else Modifier.fillMaxWidth()

                    UrlImageView(content, ContentScale.Crop, mainImageModifier, loadedImageModifier, controllerVisible, accountViewModel = accountViewModel)
                }
            }
        is MediaUrlVideo ->
            SensitivityWarning(content.contentWarning != null, accountViewModel) {
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    VideoView(
                        videoUri = content.url,
                        mimeType = content.mimeType,
                        title = content.description,
                        artworkUri = content.artworkUri,
                        borderModifier = MaterialTheme.colorScheme.videoGalleryModifier,
                        authorName = content.authorName,
                        dimensions = content.dim,
                        blurhash = content.blurhash,
                        isFiniteHeight = isFiniteHeight,
                        nostrUriCallback = content.uri,
                        accountViewModel = accountViewModel,
                    )
                }
            }
        is MediaLocalImage ->
            TwoSecondController(content) { controllerVisible ->
                val mainImageModifier = Modifier.fillMaxWidth()
                val loadedImageModifier = if (roundedCorner) MaterialTheme.colorScheme.imageModifier else Modifier.fillMaxWidth()

                LocalImageView(content, ContentScale.Crop, mainImageModifier, loadedImageModifier, controllerVisible, accountViewModel = accountViewModel)
            }
        is MediaLocalVideo ->
            content.localFile?.let {
                Box(modifier = Modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
                    VideoView(
                        videoUri = it.toUri().toString(),
                        mimeType = content.mimeType,
                        title = content.description,
                        artworkUri = content.artworkUri,
                        authorName = content.authorName,
                        borderModifier = MaterialTheme.colorScheme.videoGalleryModifier,
                        isFiniteHeight = isFiniteHeight,
                        nostrUriCallback = content.uri,
                        accountViewModel = accountViewModel,
                    )
                }
            }
    }
}

@Composable
fun TwoSecondController(
    content: BaseMediaContent,
    inner: @Composable (controllerVisible: MutableState<Boolean>) -> Unit,
) {
    val controllerVisible = remember(content) { mutableStateOf(true) }

    LaunchedEffect(content) {
        delay(2.seconds)
        controllerVisible.value = false
    }

    inner(controllerVisible)
}

@Composable
fun LocalImageView(
    content: MediaLocalImage,
    contentScale: ContentScale,
    mainImageModifier: Modifier,
    loadedImageModifier: Modifier,
    controllerVisible: MutableState<Boolean>,
    accountViewModel: AccountViewModel,
    alwayShowImage: Boolean = false,
) {
    if (content.localFileExists()) {
        val showImage =
            remember {
                mutableStateOf(
                    if (alwayShowImage) true else accountViewModel.settings.showImages.value,
                )
            }

        val ratio = remember(content) { aspectRatio(content.dim) }
        CrossfadeIfEnabled(targetState = showImage.value, contentAlignment = Alignment.Center, accountViewModel = accountViewModel) {
            if (it) {
                SubcomposeAsyncImage(
                    model = content.localFile,
                    contentDescription = content.description,
                    contentScale = contentScale,
                    modifier = mainImageModifier,
                ) {
                    val state by painter.state.collectAsState()
                    when (state) {
                        is AsyncImagePainter.State.Loading,
                        -> {
                            if (content.blurhash != null) {
                                if (ratio != null) {
                                    DisplayBlurHash(
                                        content.blurhash,
                                        content.description,
                                        contentScale,
                                        loadedImageModifier.aspectRatio(ratio),
                                    )
                                } else {
                                    DisplayBlurHash(
                                        content.blurhash,
                                        content.description,
                                        contentScale,
                                        loadedImageModifier,
                                    )
                                }
                            } else {
                                DisplayUrlWithLoadingSymbol(content)
                            }
                        }
                        is AsyncImagePainter.State.Error -> {
                            BlankNote(loadedImageModifier)
                        }
                        is AsyncImagePainter.State.Success -> {
                            SubcomposeAsyncImageContent(loadedImageModifier)

                            content.isVerified?.let {
                                AnimatedVisibility(
                                    visible = controllerVisible.value,
                                    modifier = Modifier.align(Alignment.TopEnd),
                                    enter = remember { fadeIn() },
                                    exit = remember { fadeOut() },
                                ) {
                                    Box(Modifier.align(Alignment.TopEnd), contentAlignment = Alignment.TopEnd) {
                                        HashVerificationSymbol(it)
                                    }
                                }
                            }
                        }
                        else -> {}
                    }
                }
            } else {
                if (content.blurhash != null && ratio != null) {
                    DisplayBlurHash(
                        content.blurhash,
                        content.description,
                        ContentScale.Crop,
                        loadedImageModifier
                            .aspectRatio(ratio)
                            .clickable { showImage.value = true },
                    )
                    IconButton(
                        modifier = Modifier.size(Size75dp),
                        onClick = { showImage.value = true },
                    ) {
                        DownloadForOfflineIcon(Size75dp, Color.White)
                    }
                } else {
                    ImageUrlWithDownloadButton(content.uri, showImage)
                }
            }
        }
    } else {
        BlankNote(loadedImageModifier)
    }
}

@Composable
fun UrlImageView(
    content: MediaUrlImage,
    contentScale: ContentScale,
    mainImageModifier: Modifier,
    loadedImageModifier: Modifier,
    controllerVisible: MutableState<Boolean>,
    accountViewModel: AccountViewModel,
    alwayShowImage: Boolean = false,
) {
    val ratio = content.dim?.aspectRatio()

    val showImage =
        remember {
            mutableStateOf(
                if (alwayShowImage) true else accountViewModel.settings.showImages.value,
            )
        }

    CrossfadeIfEnabled(targetState = showImage.value, contentAlignment = Alignment.Center, accountViewModel = accountViewModel) {
        if (it) {
            SubcomposeAsyncImage(
                model = content.url,
                contentDescription = content.description,
                contentScale = contentScale,
                modifier = mainImageModifier,
            ) {
                val state by painter.state.collectAsState()
                when (state) {
                    is AsyncImagePainter.State.Loading,
                    -> {
                        if (content.blurhash != null) {
                            if (ratio != null) {
                                DisplayBlurHash(
                                    content.blurhash,
                                    content.description,
                                    ContentScale.Crop,
                                    loadedImageModifier.aspectRatio(ratio),
                                )
                            } else {
                                DisplayBlurHash(
                                    content.blurhash,
                                    content.description,
                                    ContentScale.Crop,
                                    loadedImageModifier,
                                )
                            }
                        } else {
                            DisplayUrlWithLoadingSymbol(content)
                        }
                    }
                    is AsyncImagePainter.State.Error -> {
                        ClickableUrl(urlText = "${content.url} ", url = content.url)
                    }
                    is AsyncImagePainter.State.Success -> {
                        SubcomposeAsyncImageContent(loadedImageModifier)

                        AnimatedVisibility(
                            visible = controllerVisible.value,
                            modifier = Modifier.align(Alignment.TopEnd),
                            enter = remember { fadeIn() },
                            exit = remember { fadeOut() },
                        ) {
                            Box(Modifier.align(Alignment.TopEnd), contentAlignment = Alignment.TopEnd) {
                                ShowHash(content)
                            }
                        }
                    }
                    else -> {}
                }
            }
        } else {
            if (content.blurhash != null && ratio != null) {
                DisplayBlurHash(
                    content.blurhash,
                    content.description,
                    ContentScale.Crop,
                    loadedImageModifier
                        .aspectRatio(ratio)
                        .clickable { showImage.value = true },
                )
                IconButton(
                    modifier = Modifier.size(Size75dp),
                    onClick = { showImage.value = true },
                ) {
                    DownloadForOfflineIcon(Size75dp, Color.White)
                }
            } else {
                ImageUrlWithDownloadButton(content.url, showImage)
            }
        }
    }
}

@Composable
fun ImageUrlWithDownloadButton(
    url: String,
    showImage: MutableState<Boolean>,
) {
    val uri = LocalUriHandler.current

    val primary = MaterialTheme.colorScheme.primary
    val background = MaterialTheme.colorScheme.onBackground

    val regularText = remember { SpanStyle(color = background) }
    val clickableTextStyle = remember { SpanStyle(color = primary) }

    val annotatedTermsString =
        remember {
            buildAnnotatedString {
                withStyle(clickableTextStyle) {
                    pushStringAnnotation("routeToImage", "")
                    append("$url ")
                    pop()
                }

                withStyle(clickableTextStyle) {
                    pushStringAnnotation("routeToImage", "")
                    appendInlineContent("inlineContent", "[icon]")
                    pop()
                }

                withStyle(regularText) { append(" ") }
            }
        }

    val inlineContent = mapOf("inlineContent" to InlineDownloadIcon(showImage))

    val pressIndicator = remember { Modifier.fillMaxWidth().clickable { runCatching { uri.openUri(url) } } }

    Text(
        text = annotatedTermsString,
        modifier = pressIndicator,
        inlineContent = inlineContent,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

@Composable
private fun InlineDownloadIcon(showImage: MutableState<Boolean>) =
    InlineTextContent(
        Placeholder(
            width = Font17SP,
            height = Font17SP,
            placeholderVerticalAlign = PlaceholderVerticalAlign.Center,
        ),
    ) {
        IconButton(
            modifier = Modifier.size(Size20dp),
            onClick = { showImage.value = true },
        ) {
            DownloadForOfflineIcon(Size24dp)
        }
    }

@Composable
fun ShowHash(content: MediaUrlContent) {
    var verifiedHash by remember(content.url) { mutableStateOf<Boolean?>(null) }

    if (content.hash != null) {
        LaunchedEffect(key1 = content.url) {
            val newVerifiedHash =
                withContext(Dispatchers.IO) {
                    verifyHash(content)
                }
            if (newVerifiedHash != verifiedHash) {
                verifiedHash = newVerifiedHash
            }
        }
    }

    verifiedHash?.let { HashVerificationSymbol(it) }
}

fun aspectRatio(dim: Dimension?): Float? {
    if (dim == null) return null

    return dim.width.toFloat() / dim.height.toFloat()
}

@Composable
private fun DisplayUrlWithLoadingSymbol(content: BaseMediaContent) {
    val uri = LocalUriHandler.current

    val primary = MaterialTheme.colorScheme.primary
    val background = MaterialTheme.colorScheme.onBackground

    val regularText = remember { SpanStyle(color = background) }
    val clickableTextStyle = remember { SpanStyle(color = primary) }

    val annotatedTermsString =
        remember {
            buildAnnotatedString {
                if (content is MediaUrlContent) {
                    withStyle(clickableTextStyle) {
                        pushStringAnnotation("routeToImage", "")
                        append(content.url + " ")
                        pop()
                    }
                } else {
                    withStyle(regularText) { append("Loading content...") }
                }

                withStyle(clickableTextStyle) {
                    pushStringAnnotation("routeToImage", "")
                    appendInlineContent("inlineContent", "[icon]")
                    pop()
                }

                withStyle(regularText) { append(" ") }
            }
        }

    val inlineContent = mapOf("inlineContent" to InlineLoadingIcon())

    val pressIndicator =
        remember {
            if (content is MediaUrlContent) {
                Modifier.clickable { runCatching { uri.openUri(content.url) } }
            } else {
                Modifier
            }
        }

    Text(
        text = annotatedTermsString,
        modifier = pressIndicator,
        inlineContent = inlineContent,
        overflow = TextOverflow.Ellipsis,
        maxLines = 1,
    )
}

@Composable
private fun InlineLoadingIcon() =
    InlineTextContent(
        Placeholder(
            width = Font17SP,
            height = Font17SP,
            placeholderVerticalAlign = PlaceholderVerticalAlign.Center,
        ),
    ) {
        LoadingAnimation()
    }

@Composable
fun DisplayBlurHash(
    blurhash: String?,
    description: String?,
    contentScale: ContentScale,
    modifier: Modifier,
) {
    if (blurhash == null) return

    AsyncImage(
        model = Blurhash(blurhash),
        contentDescription = description,
        contentScale = contentScale,
        modifier = modifier,
    )
}

@Composable
fun ShareImageAction(
    accountViewModel: AccountViewModel,
    popupExpanded: MutableState<Boolean>,
    content: BaseMediaContent,
    onDismiss: () -> Unit,
) {
    if (content is MediaUrlContent) {
        ShareImageAction(
            accountViewModel = accountViewModel,
            popupExpanded = popupExpanded,
            videoUri = content.url,
            postNostrUri = content.uri,
            blurhash = content.blurhash,
            dim = content.dim,
            hash = content.hash,
            mimeType = content.mimeType,
            onDismiss = onDismiss,
        )
    } else if (content is MediaPreloadedContent) {
        ShareImageAction(
            accountViewModel = accountViewModel,
            popupExpanded = popupExpanded,
            videoUri = content.localFile?.toUri().toString(),
            postNostrUri = content.uri,
            blurhash = content.blurhash,
            dim = content.dim,
            hash = null,
            mimeType = content.mimeType,
            onDismiss = onDismiss,
        )
    }
}

@OptIn(ExperimentalPermissionsApi::class)
@Composable
fun ShareImageAction(
    accountViewModel: AccountViewModel,
    popupExpanded: MutableState<Boolean>,
    videoUri: String?,
    postNostrUri: String?,
    blurhash: String?,
    dim: Dimension?,
    hash: String?,
    mimeType: String?,
    onDismiss: () -> Unit,
) {
    DropdownMenu(
        expanded = popupExpanded.value,
        onDismissRequest = onDismiss,
    ) {
        val clipboardManager = LocalClipboardManager.current

        if (videoUri != null && !videoUri.startsWith("file")) {
            DropdownMenuItem(
                text = { Text(stringRes(R.string.copy_url_to_clipboard)) },
                onClick = {
                    clipboardManager.setText(AnnotatedString(videoUri))
                    onDismiss()
                },
            )
        }

        postNostrUri?.let {
            DropdownMenuItem(
                text = { Text(stringRes(R.string.copy_the_note_id_to_the_clipboard)) },
                onClick = {
                    clipboardManager.setText(AnnotatedString(it))
                    onDismiss()
                },
            )
        }
    }
}

private suspend fun verifyHash(content: MediaUrlContent): Boolean? {
    if (content.hash == null) return null

    Amethyst.instance.coilCache.openSnapshot(content.url)?.use { snapshot ->
        val hash = CryptoUtils.sha256(snapshot.data.toFile().readBytes()).toHexKey()

        Log.d("Image Hash Verification", "$hash == ${content.hash}")

        return hash == content.hash
    }

    return null
}

@Composable
private fun HashVerificationSymbol(verifiedHash: Boolean) {
    val localContext = LocalContext.current
    val openDialogMsg = remember { mutableStateOf<String?>(null) }

    openDialogMsg.value?.let {
        InformationDialog(
            title = stringRes(localContext, R.string.hash_verification_info_title),
            textContent = it,
        ) {
            openDialogMsg.value = null
        }
    }

    if (verifiedHash) {
        IconButton(
            modifier = hashVerifierMark,
            onClick = {
                openDialogMsg.value = stringRes(localContext, R.string.hash_verification_passed)
            },
        ) {
            HashCheckIcon(Size30dp)
        }
    } else {
        IconButton(
            modifier = hashVerifierMark,
            onClick = {
                openDialogMsg.value = stringRes(localContext, R.string.hash_verification_failed)
            },
        ) {
            HashCheckFailedIcon(Size30dp)
        }
    }
}
