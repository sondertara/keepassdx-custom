package com.kunzisoft.keepass.credentialprovider.autofill

import com.kunzisoft.keepass.model.EntryInfo
import com.kunzisoft.keepass.model.Passkey
import com.kunzisoft.keepass.model.SearchInfo
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AutofillMatchingEngineTest {

    @Test
    fun extractAppKeywords_commonApps_returnsCleanKeywords() {
        val spotify = AutofillMatchingEngine.extractAppKeywords("com.spotify.music")
        assertTrue(spotify.contains("spotify"))
        assertFalse(spotify.contains("music"))
        assertFalse(spotify.contains("com"))

        val github = AutofillMatchingEngine.extractAppKeywords("com.github.android")
        assertTrue(github.contains("github"))
        assertFalse(github.contains("android"))

        val youtube = AutofillMatchingEngine.extractAppKeywords("com.google.android.youtube")
        assertTrue(youtube.contains("youtube"))

        val vlc = AutofillMatchingEngine.extractAppKeywords("org.videolan.vlc")
        assertTrue(vlc.contains("vlc"))

        val telegram = AutofillMatchingEngine.extractAppKeywords("org.telegram.messenger")
        assertTrue(telegram.contains("telegram"))

        val amazon = AutofillMatchingEngine.extractAppKeywords("com.amazon.mShop.android.shopping")
        assertTrue(amazon.contains("amazon"))

        val zhihu = AutofillMatchingEngine.extractAppKeywords("com.zhihu.android")
        assertTrue(zhihu.contains("zhihu"))
    }

    @Test
    fun extractAppKeywords_specialAndKnownAliases_returnsExpectedKeywords() {
        val bili = AutofillMatchingEngine.extractAppKeywords("tv.danmaku.bili")
        assertTrue(bili.contains("bilibili") || bili.contains("bili"))

        val wechat = AutofillMatchingEngine.extractAppKeywords("com.tencent.mm")
        assertTrue(wechat.contains("wechat") || wechat.contains("weixin"))

        val steam = AutofillMatchingEngine.extractAppKeywords("com.valvesoftware.android.steam.community")
        assertTrue(steam.contains("steam"))

        val twitter = AutofillMatchingEngine.extractAppKeywords("com.twitter.android")
        assertTrue(twitter.contains("twitter") || twitter.contains("x"))

        val edge = AutofillMatchingEngine.extractAppKeywords("com.microsoft.emmx")
        assertTrue(edge.contains("edge"))
    }

    @Test
    fun extractAppKeywords_emptyAndNull_returnsEmpty() {
        assertTrue(AutofillMatchingEngine.extractAppKeywords(null).isEmpty())
        assertTrue(AutofillMatchingEngine.extractAppKeywords("").isEmpty())
        assertTrue(AutofillMatchingEngine.extractAppKeywords("   ").isEmpty())
    }

    @Test
    fun extractDomainKeywords_subdomainsAndTLDs_returnsBrandAndRoot() {
        val jetbrains = AutofillMatchingEngine.extractDomainKeywords("account.jetbrains.com")
        assertTrue(jetbrains.contains("jetbrains"))
        assertTrue(jetbrains.contains("jetbrains.com"))

        val tesla = AutofillMatchingEngine.extractDomainKeywords("auth.tesla.com")
        assertTrue(tesla.contains("tesla"))
        assertTrue(tesla.contains("tesla.com"))

        val live = AutofillMatchingEngine.extractDomainKeywords("login.live.com")
        assertTrue(live.contains("live"))
        assertTrue(live.contains("live.com"))

        val cloudflare = AutofillMatchingEngine.extractDomainKeywords("https://dash.cloudflare.com/login")
        assertTrue(cloudflare.contains("cloudflare"))

        val github = AutofillMatchingEngine.extractDomainKeywords("http://api.github.com:8080/auth")
        assertTrue(github.contains("github"))
    }

    @Test
    fun calculateRelevance_exactAndFuzzyMatching_scoresAccurately() {
        val entryExact = EntryInfo().apply {
            title = "Spotify"
            username = "user@test.com"
        }
        val scoreExact = AutofillMatchingEngine.calculateRelevance(
            entry = entryExact,
            keywords = listOf("spotify"),
            rawIdentifier = "com.spotify.music"
        )
        assertTrue("Exact title match should score high", scoreExact >= 100)

        val entryPrefix = EntryInfo().apply {
            title = "Spotify Premium"
            username = "user@test.com"
        }
        val scorePrefix = AutofillMatchingEngine.calculateRelevance(
            entry = entryPrefix,
            keywords = listOf("spotify"),
            rawIdentifier = "com.spotify.music"
        )
        assertTrue("Prefix title match should score >= 85", scorePrefix >= 85)

        val entryUrlMatch = EntryInfo().apply {
            title = "Music Stream"
            url = "https://open.spotify.com"
            username = "user@test.com"
        }
        val scoreUrl = AutofillMatchingEngine.calculateRelevance(
            entry = entryUrlMatch,
            keywords = listOf("spotify"),
            rawIdentifier = "com.spotify.music"
        )
        assertTrue("URL match should score >= 50", scoreUrl >= 50)

        val entryUnrelated = EntryInfo().apply {
            title = "Netflix"
            url = "https://netflix.com"
        }
        val scoreUnrelated = AutofillMatchingEngine.calculateRelevance(
            entry = entryUnrelated,
            keywords = listOf("spotify"),
            rawIdentifier = "com.spotify.music"
        )
        assertTrue("Unrelated entry should score below threshold", scoreUnrelated < AutofillMatchingEngine.MATCH_THRESHOLD)
    }

    @Test
    fun calculateRelevance_passkeyBonus_increasesScore() {
        val entryPlain = EntryInfo().apply {
            title = "GitHub"
            username = "octocat"
        }
        val entryWithPasskey = EntryInfo().apply {
            title = "GitHub"
            username = "octocat"
            passkey = Passkey(
                username = "octocat",
                privateKeyPem = "pem".toCharArray(),
                credentialId = "cred123",
                userHandle = "handle",
                relyingParty = "github.com",
                backupEligibility = true,
                backupState = true
            )
        }

        val plainScore = AutofillMatchingEngine.calculateRelevance(
            entry = entryPlain,
            keywords = listOf("github"),
            rawIdentifier = "com.github.android"
        )
        val passkeyScore = AutofillMatchingEngine.calculateRelevance(
            entry = entryWithPasskey,
            keywords = listOf("github"),
            rawIdentifier = "com.github.android"
        )

        assertTrue("Passkey entry should receive a quality bonus", passkeyScore > plainScore)
    }

    @Test
    fun rankEntries_prioritizesPasskeyAndExactMatches() {
        val passkeyEntry = EntryInfo().apply {
            title = "GitHub"
            username = "alice"
            passkey = Passkey(
                username = "alice",
                privateKeyPem = "pem".toCharArray(),
                credentialId = "cred123",
                userHandle = "handle",
                relyingParty = "github.com",
                backupEligibility = true,
                backupState = true
            )
        }
        val plainEntry = EntryInfo().apply {
            title = "GitHub"
            username = "bob"
        }
        val fuzzyEntry = EntryInfo().apply {
            title = "Old GitHub Backup"
            username = "charlie"
        }

        val searchInfo = SearchInfo().apply {
            applicationId = "com.github.android"
        }

        val ranked = AutofillMatchingEngine.rankEntries(
            entries = listOf(fuzzyEntry, plainEntry, passkeyEntry),
            searchInfo = searchInfo
        )

        assertEquals("Passkey-enabled entry should be ranked first", passkeyEntry, ranked[0])
        assertEquals("Exact title match should be ranked second", plainEntry, ranked[1])
        assertEquals("Fuzzy title match should be ranked third", fuzzyEntry, ranked[2])
    }
}
