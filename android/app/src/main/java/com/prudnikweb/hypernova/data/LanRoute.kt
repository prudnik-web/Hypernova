package com.prudnikweb.hypernova.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.prudnikweb.hypernova.BuildConfig
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Dispatcher
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.json.JSONObject
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.URI
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.io.IOException
import kotlin.coroutines.resume
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/*
 * The local network route (docs/PROTOCOL.md, "Local network (direct HTTPS)"): the daemon listens
 * on the Mac's own addresses with a self-signed certificate the pairing code vouched for, and asks
 * this phone for its device certificate. On Wi-Fi, or while this phone is the hotspot the Mac sits
 * on, the app tries those addresses and prefers the first good mutual-TLS handshake; otherwise, or
 * when none answers, it uses the paired base URL (Tailscale). Nothing here opens anything to the
 * internet.
 */

/** The daemon's local listener as the snapshot (or a `{t:"lan"}` message) describes it. */
@Immutable
data class LanInfo(
    val port: Int,
    /** The Mac's current private IPv4/IPv6 addresses. */
    val addresses: List<String>,
    /** Lowercase hex SHA-256 of the listener's certificate (DER). */
    val fingerprint: String,
    /** The Mac holds a device certificate for this phone (else the app asks for one). */
    val deviceCert: Boolean,
) {
    companion object {
        fun parse(o: JSONObject?): LanInfo? {
            if (o == null) return null
            val fp = o.str("fingerprint")?.lowercase()?.takeIf { it.length == 64 } ?: return null
            return LanInfo(
                port = o.int("port") ?: DEFAULT_PORT,
                addresses = o.arr("addresses").strings().map { it.trim() }.filter { it.isNotEmpty() },
                fingerprint = fp,
                deviceCert = o.bool("deviceCert"),
            )
        }

        const val DEFAULT_PORT = 47323
    }
}

/**
 * How the app reaches the computer right now: its own network, the app's built-in Tailscale node
 * (data/Tsnet.kt), or the paired base URL as it is (the Tailscale app on the phone, or a public
 * address). Preferred in that order.
 */
enum class RouteKind { Local, Tailscale, Remote }

/**
 * Where requests go: a base URL and the client that fits it (pinned for the local route, with the
 * pin and the device certificate it holds, which an in-app page there needs too: [LocalPage]).
 */
class NetRoute(val base: String, val kind: RouteKind, val client: OkHttpClient, val fingerprint: String? = null, val identity: DeviceIdentity? = null) {
    /** Uploads queue on their own, so prompts and approvals never wait behind a big file. */
    val uploads: OkHttpClient by lazy {
        if (client === Net.client) Net.uploads
        else client.newBuilder().dispatcher(Dispatcher()).writeTimeout(2, TimeUnit.MINUTES).readTimeout(2, TimeUnit.MINUTES).build()
    }

    companion object {
        fun remote(base: String) = NetRoute(base, RouteKind.Remote, Net.client)
    }
}

/** The built-in Tailscale node's view of the computer: where to dial it, and how. */
data class TailnetTarget(
    /** `https://<tailnet name>:port`, or `https://<tailnet address>:port` when the tailnet has no HTTPS certificates. */
    val base: String,
    /** The computer's own certificate, pinned, for the address form. */
    val fingerprint: String?,
) {
    /** "host:port" (an IPv6 address in brackets), what the proxy is allowed to tunnel to. */
    val hostPort: String? get() = RoutePolicy.originOf(base)?.let { "${if (it.host.contains(':')) "[${it.host}]" else it.host}:${it.port}" }

    companion object {
        /**
         * The target a pairing names: its base URL when it is on the tailnet, else the tailnet name
         * or address from the pairing link; null when the pairing says nothing about a tailnet.
         */
        fun of(p: Pairing): TailnetTarget? {
            // Where the computer said it serves now (TailnetFollow), when it moved since the pairing.
            p.tailnetUrl?.let { u -> if (RoutePolicy.originOf(u)?.scheme == "https") return TailnetTarget(u, p.fingerprint) }
            val o = RoutePolicy.originOf(p.baseUrl) ?: return null
            val name = p.tailnetName?.lowercase()
            val ip = p.tailnetIp
            if (o.scheme == "https" && (o.host == name || o.host == ip)) return TailnetTarget(p.baseUrl, p.fingerprint)
            if (name != null) return TailnetTarget("https://$name:${o.port}", p.fingerprint)
            return null
        }
    }
}

/**
 * The routes in use, by paired base URL. Every [Api] made for a base looks here first, so whatever
 * the app builds from the base URL (pictures, downloads, previews, read aloud, the terminal's
 * socket) follows the active route without each caller knowing about routes. The app's WebViews
 * can't use the pinned client, so on the local route the app steps in: a page's WebView asks it
 * about the certificate ([LocalPage]), and the terminal's socket, which a WebView never asks about,
 * the app opens itself ([TermTicket]).
 */
object ActiveRoutes {
    private val routers = ConcurrentHashMap<String, LanRouter>()

    fun register(base: String, r: LanRouter) { routers[base.trimEnd('/')] = r }
    fun unregister(base: String, r: LanRouter) { routers.remove(base.trimEnd('/'), r) }
    fun route(base: String): NetRoute = routers[base.trimEnd('/')]?.route ?: NetRoute.remote(base)

    /**
     * The local route [url] is on, if any: an in-app page there carries that route's pin and
     * device certificate (ui/web/WebScreen.kt).
     */
    fun localPage(url: String): LocalPage? = routers.entries.firstNotNullOfOrNull { (base, r) ->
        val route = r.route
        val fp = route.fingerprint
        if (route.kind == RouteKind.Local && fp != null && RoutePolicy.sameOrigin(url, route.base)) LocalPage(route.base, base, fp, route.identity) else null
    }
}

/**
 * A page from the Mac's local listener in the app's own WebView (ui/web/WebScreen.kt), held to the
 * pinned client's rules: it trusts exactly the pinned certificate, and shows this phone's device
 * certificate to that listener alone. A browser outside the app can do neither, so it gets the
 * same page by the paired base URL ([outside]).
 */
class LocalPage(val base: String, val remoteBase: String, val fingerprint: String, val identity: DeviceIdentity?) {
    /** Whether to go on past a certificate error: only for the pinned certificate, in its dates. */
    fun trusts(cert: X509Certificate?, now: Long = System.currentTimeMillis()): Boolean =
        Pin.check(cert?.let { arrayOf(it) }, fingerprint, now) == PinResult.Ok

    /** The identity for a server at [host]:[port] that asks for one: the local listener's own address only. */
    fun identityFor(host: String?, port: Int): DeviceIdentity? {
        val o = RoutePolicy.originOf(base) ?: return null
        return identity?.takeIf { host != null && RoutePolicy.hostOf(host) == o.host && port == o.port }
    }

    /** [url] by the paired base URL when it's on this listener: for a browser outside the app. */
    fun outside(url: String): String = if (RoutePolicy.sameOrigin(url, base)) RoutePolicy.rebase(url, remoteBase) else url
}

// ─── The pin ────────────────────────────────────────────────────────────────

/** Why a pinned certificate was refused. */
enum class PinResult { Ok, Wrong, Expired, Missing }

/**
 * A trust decision from the pairing code alone: the server's certificate must be the very one the
 * fingerprint names, and it must be in its validity dates. Hostnames are IP addresses here, so the
 * pin replaces the hostname check.
 */
object Pin {
    fun fingerprint(cert: X509Certificate): String = sha256Hex(cert.encoded)

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    fun check(chain: Array<out X509Certificate>?, fingerprint: String, now: Long = System.currentTimeMillis()): PinResult {
        val leaf = chain?.firstOrNull() ?: return PinResult.Missing
        if (!fingerprint(leaf).equals(fingerprint, ignoreCase = true)) return PinResult.Wrong
        if (now < leaf.notBefore.time || now > leaf.notAfter.time) return PinResult.Expired
        return PinResult.Ok
    }

    /** A trust manager that accepts exactly the certificate [fingerprint] names. */
    fun trustManager(fingerprint: String, now: () -> Long = System::currentTimeMillis): X509TrustManager = object : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
            throw java.security.cert.CertificateException("not a server")

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            when (val r = check(chain, fingerprint, now())) {
                PinResult.Ok -> Unit
                else -> throw java.security.cert.CertificateException("pinned certificate: $r")
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}

/** An OkHttp client for the local route: the pin as its only trust, the device certificate as its identity. */
object PinnedTls {
    fun client(fingerprint: String, identity: DeviceIdentity?, connectTimeoutMs: Long = 4_000): OkHttpClient {
        val tm = Pin.trustManager(fingerprint)
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(identity?.let { arrayOf(it.keyManager()) }, arrayOf(tm), SecureRandom())
        return OkHttpClient.Builder()
            .sslSocketFactory(ctx.socketFactory, tm)
            // The pin is the identity check; the "hostname" is an IP address.
            .hostnameVerifier { _, _ -> true }
            .connectTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .pingInterval(20, TimeUnit.SECONDS)
            .build()
    }

    /**
     * The hotspot sweep's client: the same pin and identity, a dispatcher of its own that runs a
     * whole wave at once (OkHttp's default stops at 64), and a short connect timeout, as an address
     * with nobody on it never answers.
     */
    fun sweep(client: OkHttpClient): OkHttpClient = client.newBuilder()
        .dispatcher(Dispatcher().apply { maxRequests = RoutePolicy.PARALLEL; maxRequestsPerHost = RoutePolicy.PARALLEL })
        .connectTimeout(RoutePolicy.SWEEP_CONNECT_MS, TimeUnit.MILLISECONDS)
        .build()
}

// ─── Choosing the route ─────────────────────────────────────────────────────

/** What the phone is on, as far as the route cares. */
enum class NetKind { None, Mobile, Wifi }

/**
 * The route decision, with nothing of Android in it (unit-tested). The local addresses are worth
 * trying on Wi-Fi (the Mac may share it) and while this phone hosts a hotspot (the Mac may be on
 * it); on mobile data alone the Mac can't be next door, so the remote route it is.
 */
object RoutePolicy {
    /** At most this many addresses go into one probe: the known ones plus a /24 of a hotspot. */
    const val MAX_CANDIDATES = 300
    /**
     * While on the remote route with local addresses worth trying, try them again after this long,
     * then twice as long after each try, up to [RECHECK_MAX_MS]; a network change, or a hotspot appearing, starts over ([RecheckBackoff]).
     * (Every 2 minutes for hours on end, with a hotspot's /24 swept each time, kept the radio and
     * the phone warm for an answer that rarely changes without the network changing.)
     */
    const val RECHECK_MS = 120_000L
    const val RECHECK_MAX_MS = 30 * 60_000L
    /** How long one address gets to answer. */
    const val PROBE_TIMEOUT_MS = 4_000L
    /** How long the computer gets to answer through the built-in node (a first dial includes finding it). */
    const val NODE_PROBE_MS = 12_000L
    /** How long the paired base URL, as it is, gets to answer (a tailnet name with no Tailscale app fails at once). */
    const val BASE_PROBE_MS = 8_000L
    /**
     * How long a route that fails in use again and again (within minutes of the last failure) is
     * tried after the others: 8 s, then 16, 32… up to 2 minutes. Only that route's: Local is never
     * held back by the tailnet failing, nor the other way round ([RouteChooser.failedInUse]).
     */
    const val FAILED_RECHECK_MS = 8_000L

    /** After [failures] more failures in a row (within minutes of each other): 8 s, 16 s, 32 s… up to 2 minutes. */
    fun failedRecheckMs(failures: Int): Long = minOf(RECHECK_MS, FAILED_RECHECK_MS shl failures.coerceIn(0, 8))

    /** How often the router looks at the network while not on the Local route (cheap: no probe unless a re-check is due). */
    const val TICK_MS = 30_000L
    /**
     * On Wi-Fi in the same subnet as the Mac (it is most likely right there) while on another route,
     * Local is looked for after 30 s, 1 minute, then every 2 minutes: one handshake to a known address.
     */
    const val NEAR_RECHECK_MS = 30_000L

    fun nearRecheckMs(tries: Int): Long = minOf(RECHECK_MS, NEAR_RECHECK_MS shl tries.coerceIn(0, 8))
    /** A route a round settled on is used as is by an attempt to connect this soon after (no second round). */
    const val FRESH_MS = 3_000L

    /**
     * Whether this phone is on the same IPv4 subnet as any of the Mac's addresses: [phone] is this
     * phone's addresses with their prefix lengths (Wi-Fi's, a hotspot's), [mac] the Mac's. Then
     * Local is all but certain to answer, so it is tried at once and waited for.
     */
    fun sameSubnet(phone: List<Pair<String, Int>>, mac: List<String>): Boolean {
        val macs = mac.mapNotNull(::v4)
        if (macs.isEmpty()) return false
        for ((addr, prefix) in phone) {
            if (prefix !in 8..30) continue
            val a = v4(addr) ?: continue
            val mask = (-1L shl (32 - prefix)) and 0xffffffffL
            if (macs.any { (it and mask) == (a and mask) }) return true
        }
        return false
    }

    /** An IPv4 address as a number, or null. */
    private fun v4(a: String): Long? {
        val p = a.trim().split('.')
        if (p.size != 4) return null
        var n = 0L
        for (x in p) n = (n shl 8) or (x.toIntOrNull()?.takeIf { it in 0..255 } ?: return null).toLong()
        return n
    }

    /**
     * What a failed probe or request says about the route (unit-tested): refused, no answer, no
     * such name, a certificate that isn't the paired one, the built-in node unable to reach the
     * Mac (its proxy's 502)… and a short detail where the verdict alone doesn't say enough.
     */
    fun classify(e: Throwable): Pair<ConnResult, String?> {
        val chain = generateSequence(e) { c -> c.cause?.takeIf { it !== c } }.take(8).toList()
        chain.firstNotNullOfOrNull { c ->
            val m = c.message ?: return@firstNotNullOfOrNull null
            when {
                c is java.security.cert.CertificateException && m.contains("pinned certificate: Wrong") -> ConnResult.PinWrong
                c is java.security.cert.CertificateException && m.contains("pinned certificate: Expired") -> ConnResult.PinExpired
                else -> null
            }
        }?.let { return it to null }
        val connect = Regex("""Unexpected response code for CONNECT: (\d{3})""")
        chain.firstNotNullOfOrNull { c -> c.message?.let { connect.find(it) }?.groupValues?.get(1)?.toIntOrNull() }?.let { code ->
            return (if (code == 502) ConnResult.NoPeer else ConnResult.ProxyRefused) to "proxy $code"
        }
        val words = chain.mapNotNull { it.message?.lowercase() }
        return when {
            chain.any { it is java.net.UnknownHostException } -> ConnResult.NoName to null
            chain.any { it is java.net.NoRouteToHostException } || words.any { "unreachable" in it } -> ConnResult.Unreachable to null
            words.any { "refused" in it } -> ConnResult.Refused to null
            // An open connection cut (the Mac's end went, or the network under it).
            words.any { "connection reset" in it || "broken pipe" in it } -> ConnResult.Closed to "connection reset"
            chain.any { it is java.net.SocketTimeoutException } || words.any { "timed out" in it || it == "timeout" } -> ConnResult.Timeout to null
            chain.any { it is java.net.ConnectException } -> ConnResult.Unreachable to null
            chain.any { it is javax.net.ssl.SSLException } -> ConnResult.Tls to (e.message?.take(80))
            else -> ConnResult.Failed to "${e.javaClass.simpleName}: ${e.message ?: ""}".take(100)
        }
    }

    /** The most telling of several failures (a wrong certificate says more than a timeout). */
    fun worst(results: Collection<ConnResult>): ConnResult? =
        listOf(ConnResult.PinWrong, ConnResult.PinExpired, ConnResult.Refused, ConnResult.Tls, ConnResult.Http, ConnResult.NoPeer, ConnResult.ProxyRefused, ConnResult.Unreachable, ConnResult.Timeout, ConnResult.NoName, ConnResult.Failed)
            .firstOrNull { it in results }
    /** At most this many probes at once (OkHttp gives each a thread): a /24 goes in two waves. */
    const val PARALLEL = 128
    /**
     * The hotspot sweep's connect timeout: a host on the phone's own hotspot answers within
     * milliseconds, an address with nobody on it never (the connect would wait out ARP).
     */
    const val SWEEP_CONNECT_MS = 1_500L

    fun shouldProbe(net: NetKind, hotspot: Boolean): Boolean = net == NetKind.Wifi || hotspot

    /** How long the re-check waits after [tries] periodic tries since the network last changed: 2, 4, 8, 16, then 30 minutes. */
    fun recheckDelayMs(tries: Int): Long =
        if (tries >= 5) RECHECK_MAX_MS else minOf(RECHECK_MAX_MS, RECHECK_MS shl tries.coerceAtLeast(0))

    /**
     * The addresses to try, in order: those the Mac said ([known], the last snapshot's and the
     * pairing link's), then each hotspot's /24 (this phone is its gateway `x.y.z.1`; the Mac is any
     * other host on it). Duplicates once, the gateway itself never.
     */
    fun candidates(known: List<String>, hotspotGateways: List<String>): List<String> {
        val out = LinkedHashSet<String>()
        for (a in known) a.trim().takeIf { it.isNotEmpty() }?.let(out::add)
        for (g in hotspotGateways) {
            val parts = g.split('.')
            if (parts.size != 4 || parts.any { it.toIntOrNull() !in 0..255 }) continue
            val prefix = parts.take(3).joinToString(".")
            for (h in 1..254) {
                val a = "$prefix.$h"
                if (a != g) out.add(a)
            }
        }
        return out.take(MAX_CANDIDATES)
    }

    /** `https://addr:port`, with the brackets an IPv6 address needs. */
    fun baseOf(address: String, port: Int): String {
        val a = address.trim().substringBefore('%')
        return if (a.contains(':') && !a.startsWith("[")) "https://[$a]:$port" else "https://$a:$port"
    }

    /**
     * Probes the candidates, [parallel] at a time in their order (the known addresses first; a
     * hotspot's /24 in waves, each probe with [timeoutMs] from its own start, so every address gets
     * its turn within the round), and answers with the first one whose [probe] succeeds, in the
     * order they answer (the nearest is the quickest); null when none does. The rest are cancelled
     * as soon as one wins.
     */
    suspend fun choose(candidates: List<String>, timeoutMs: Long = PROBE_TIMEOUT_MS, parallel: Int = PARALLEL, probe: suspend (String) -> Boolean): String? {
        if (candidates.isEmpty()) return null
        val width = parallel.coerceAtLeast(1)
        // Fair: the probes get their turns in the candidates' order.
        val gate = Semaphore(width)
        val waves = (candidates.size + width - 1) / width
        return withTimeoutOrNull(timeoutMs * waves + 500) {
            coroutineScope {
                val results = Channel<String?>(candidates.size)
                val jobs = candidates.map { c ->
                    launch {
                        val ok = gate.withPermit {
                            try { withTimeoutOrNull(timeoutMs) { probe(c) } == true } catch (e: CancellationException) { throw e } catch (_: Throwable) { false }
                        }
                        results.send(if (ok) c else null)
                    }
                }
                var winner: String? = null
                var left = candidates.size
                while (winner == null && left > 0) {
                    winner = results.receive()
                    left--
                }
                jobs.forEach { it.cancel() }
                winner
            }
        }
    }

    /** A URL's scheme, host (lowercase, no brackets) and port (the scheme's own when none). */
    data class Origin(val scheme: String, val host: String, val port: Int)

    fun originOf(url: String): Origin? = runCatching {
        val u = URI(url.trim())
        val scheme = u.scheme?.lowercase() ?: return null
        val host = u.host?.let(::hostOf)?.takeIf { it.isNotEmpty() } ?: return null
        val port = if (u.port >= 0) u.port else when (scheme) { "https", "wss" -> 443; "http", "ws" -> 80; else -> -1 }
        Origin(scheme, host, port)
    }.getOrNull()

    fun hostOf(host: String): String = host.trim().removePrefix("[").removeSuffix("]").lowercase()

    fun sameOrigin(a: String, b: String): Boolean = originOf(a)?.let { it == originOf(b) } ?: false

    /**
     * [url]'s path, query and fragment on [base] (an origin): the same page by another route. A page
     * the Mac hands out (a preview, the checklist) works on either of its origins.
     */
    fun rebase(url: String, base: String): String {
        val u = runCatching { URI(url.trim()) }.getOrNull() ?: return url
        val path = u.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        return base.trimEnd('/') + path + (u.rawQuery?.let { "?$it" } ?: "") + (u.rawFragment?.let { "#$it" } ?: "")
    }
}

/**
 * A route chooser's clock-free core, so the policy around re-checks is testable: which route to
 * hold given the network, the known addresses and the last probe's outcome.
 */
class RouteChooser(private val remoteBase: String, private val port: Int, private val tailnet: TailnetTarget? = null) {
    var kind: RouteKind = RouteKind.Remote
        private set
    var localBase: String? = null
        private set
    /** Where the Mac answered last (on a hotspot, often an address it hasn't reported yet): tried first next time. */
    var lastWinner: String? = null
        private set

    /**
     * The result of a probe round: a winning local address, or none; and whether the computer
     * answered through the built-in Tailscale node. Local first, then Tailscale, then the base URL.
     */
    fun settle(winner: String?, tailscale: Boolean = false, lanPort: Int = port) {
        when {
            // The port the winner answered on: the Mac's latest word (its snapshot), not only the pairing link's.
            winner != null -> { kind = RouteKind.Local; localBase = RoutePolicy.baseOf(winner, lanPort); lastWinner = winner }
            tailscale && tailnet != null -> { kind = RouteKind.Tailscale; localBase = null }
            else -> { kind = RouteKind.Remote; localBase = null }
        }
    }

    /** The addresses the Mac is known by, the last one to answer first. */
    fun known(reported: List<String>): List<String> = listOfNotNull(lastWinner) + reported

    /**
     * The route in use failed (the Mac moved, the Wi-Fi went, the node lost the tailnet): back to
     * the base URL until the next probe.
     */
    fun localFailed() { kind = RouteKind.Remote; localBase = null }

    private class Health(var failures: Int = 0, var lastFailAt: Long = Long.MIN_VALUE / 2, var heldUntil: Long = Long.MIN_VALUE / 2)
    private val health = HashMap<RouteKind, Health>()

    /**
     * [k] failed in use at [now] (the snapshot or the socket over it). A first failure is a hiccup:
     * the route is tried again first. Failing again within minutes of the last, it is tried after
     * the others for 8 s, then 16, 32… up to 2 minutes ([RoutePolicy.failedRecheckMs]), still tried,
     * and still used when nothing else answers. Each route counts its own: one failing never holds
     * another back. Returns how long it is held back (0: not).
     */
    fun failedInUse(k: RouteKind, now: Long): Long {
        val h = health.getOrPut(k) { Health() }
        h.failures = if (now - h.lastFailAt > HEALTH_WINDOW_MS) 1 else h.failures + 1
        h.lastFailAt = now
        val hold = if (h.failures >= 2) RoutePolicy.failedRecheckMs(h.failures - 2) else 0L
        h.heldUntil = now + hold
        return hold
    }

    /** [k] is tried after the others until [until] (it answered, but can't be used: no device certificate, say). */
    fun hold(k: RouteKind, until: Long) {
        val h = health.getOrPut(k) { Health() }
        h.heldUntil = maxOf(h.heldUntil, until)
    }

    /** The routes tried after the others at [now]. */
    fun demoted(now: Long): Set<RouteKind> = health.filterValues { now < it.heldUntil }.keys.toSet()

    val base: String get() = when (kind) {
        RouteKind.Local -> localBase ?: remoteBase
        RouteKind.Tailscale -> tailnet?.base ?: remoteBase
        RouteKind.Remote -> remoteBase
    }

    /**
     * Whether a periodic re-check is due: not on the local route (the best there is), and only with
     * something to try: local addresses on a network they could be on, or the tailnet while the
     * node runs and the route isn't it yet.
     */
    fun wantsRecheck(net: NetKind, hotspot: Boolean, known: List<String>, hotspotGateways: List<String>, nodeRunning: Boolean = false): Boolean {
        if (kind == RouteKind.Local) return false
        val local = RoutePolicy.shouldProbe(net, hotspot) && RoutePolicy.candidates(this.known(known), hotspotGateways).isNotEmpty()
        return local || (kind == RouteKind.Remote && nodeRunning && tailnet != null)
    }

    companion object {
        /** Failures further apart than this start the count over. */
        const val HEALTH_WINDOW_MS = 5 * 60_000L
    }
}

/**
 * The clock-free back-off for the periodic re-check (the sweep): a check of the network is cheap
 * and happens every [RoutePolicy.TICK_MS]; the re-check itself is due at 2, 4, 8, 16, then 30
 * minutes after the last. A hotspot switched on later, or the Mac joining it, doesn't change the
 * default network, so a gateway appearing (or the Wi-Fi network being another one) starts over.
 * In the same subnet as the Mac ([near]) it is due at once, then after 30 s, 1 minute, then every 2
 * ([RoutePolicy.nearRecheckMs]): the Mac is most likely right there, and one handshake costs little.
 */
class RecheckBackoff(now: Long) {
    private var tries = 1
    private var dueAt = now + RoutePolicy.recheckDelayMs(0)
    private var hadGateways = false
    private var seen = false
    private var networkId: Any? = null
    private var wasNear = false

    /** Whether the re-check is due at [now], given what the cheap check saw; counts it as run when it is. */
    fun due(now: Long, gateways: List<String>, network: Any?, near: Boolean = false): Boolean {
        if ((gateways.isNotEmpty() && !hadGateways) || (seen && network != networkId) || (near && !wasNear)) { tries = 0; dueAt = now }
        hadGateways = gateways.isNotEmpty()
        networkId = network
        wasNear = near
        seen = true
        if (now < dueAt) return false
        dueAt = now + if (near) RoutePolicy.nearRecheckMs(tries++) else RoutePolicy.recheckDelayMs(tries++)
        return true
    }
}

/** One route as a probe round found it: its answer, where it was tried, how long it took, and why it wasn't, when it wasn't. */
@Immutable
data class RouteTry(val route: RouteKind, val result: ConnResult, val target: String? = null, val ms: Long? = null, val why: String? = null) {
    val tried: Boolean get() = result != ConnResult.Skipped
}

/**
 * A probe round's story: the network it saw, each route's answer, and the route it chose (null:
 * none answered, and the base URL is the fallback). The offline card words its problem from it.
 */
@Immutable
data class RouteReport(
    val at: Long,
    val net: NetKind,
    /** On Wi-Fi in the same subnet as one of the Mac's addresses. */
    val near: Boolean,
    val tries: List<RouteTry>,
    val winner: RouteKind?,
) {
    fun of(k: RouteKind): RouteTry? = tries.lastOrNull { it.route == k }
}

/**
 * When a probe round may settle, and on what (unit-tested). Every route is tried at once; the
 * order of preference is Local, the built-in node, the base URL, with a route that keeps failing in
 * use ([demoted]) after the others. A round settles on the best route that answered as soon as
 * nothing better is still being tried, with one exception each way:
 * - Local still being tried holds the round up only where it's likely to answer ([waitForLocal]:
 *   the same subnet as the Mac, or this phone's hotspot); elsewhere the round settles on what
 *   answered and moves to Local if it answers later ([upgrade]), so a reconnect never waits on
 *   Local timing out on a café's Wi-Fi.
 * - A held-back route that answered waits for the others still being tried.
 */
class RoundJudge(private val waitForLocal: Boolean, private val demoted: Set<RouteKind> = emptySet()) {
    private val order = listOf(RouteKind.Local, RouteKind.Tailscale, RouteKind.Remote)
    private fun rank(k: RouteKind) = order.indexOf(k) + if (k in demoted) order.size else 0

    /** The route to settle on now, given the routes that [answered] and those still [pending]; null: wait. */
    fun settle(answered: Set<RouteKind>, pending: Set<RouteKind>): RouteKind? {
        val best = answered.minByOrNull(::rank) ?: return null
        val better = pending.filter { rank(it) < rank(best) }
        if (better.isEmpty()) return best
        if (best in demoted) return null
        // Only Local is worth waiting for, and only where it's likely.
        return if (RouteKind.Local in better && waitForLocal) null else best
    }

    /** After settling on [current], whether [k] answering is worth moving to: Local, not held back. */
    fun upgrade(current: RouteKind, k: RouteKind): Boolean = k == RouteKind.Local && current != RouteKind.Local && k !in demoted

    /** Whether, settled on [current], a route still [pending] could still improve on it ([upgrade]). */
    fun mayImprove(current: RouteKind, pending: Set<RouteKind>): Boolean = pending.any { upgrade(current, it) }
}

/** What the offline card says about the routes, from the last round (unit-tested). */
enum class RouteProblem {
    /** Tried Local and the tailnet: neither answered. */
    Both,
    /** Tried Local; the tailnet wasn't tried (no node running, or no tailnet in the pairing). */
    LocalOnly,
    /** Local wasn't tried (not on Wi-Fi); the tailnet was and didn't answer. */
    TailnetOnly,
    /** Local answered with a certificate that isn't the paired one, and nothing else answered. */
    WrongMac,
}

object RouteWords {
    /** A route's answer in the log's words. */
    fun result(r: ConnResult): String = when (r) {
        ConnResult.Ok -> "answered"
        ConnResult.Refused -> "refused"
        ConnResult.Timeout -> "no answer"
        ConnResult.Unreachable -> "unreachable"
        ConnResult.NoName -> "no such name"
        ConnResult.PinWrong -> "another certificate"
        ConnResult.PinExpired -> "certificate out of date"
        ConnResult.Tls -> "TLS failed"
        ConnResult.NoPeer -> "not reachable on the tailnet"
        ConnResult.ProxyRefused -> "the node's proxy refused"
        ConnResult.Http -> "an error status"
        ConnResult.Closed -> "closed"
        ConnResult.Failed -> "failed"
        ConnResult.Skipped -> "not tried"
        ConnResult.Info -> "noted"
    }

    /** Why a round chose what it did, for the log: "the built-in node answered; Local refused". */
    fun summary(rep: RouteReport, upgrade: Boolean): String {
        fun part(k: RouteKind, name: String): String? = rep.of(k)?.takeIf { k != rep.winner }?.let { t ->
            if (t.tried) "$name ${result(t.result)}" else "$name not tried (${t.why ?: "nothing to try"})"
        }
        val others = listOfNotNull(part(RouteKind.Local, "Local"), part(RouteKind.Tailscale, "tailnet"), part(RouteKind.Remote, "base URL")).joinToString(", ")
        fun and(s: String) = if (others.isEmpty()) s else "$s; $others"
        return when (rep.winner) {
            RouteKind.Local -> if (upgrade) and("Local answered after all: moving to it") else and("Local answered")
            RouteKind.Tailscale -> and("the built-in node answered")
            RouteKind.Remote -> and("the base URL answered as it is")
            null -> "nothing answered${if (others.isEmpty()) "" else ": $others"}; the base URL is the fallback"
        }
    }

    /** Which sentence fits [r] when the link failed; null: none of these (the problem's own words serve). */
    fun problem(r: RouteReport?): RouteProblem? {
        if (r == null || r.winner != null) return null
        val local = r.of(RouteKind.Local)?.takeIf { it.tried }
        val tail = r.of(RouteKind.Tailscale)?.takeIf { it.tried }
        return when {
            local?.result == ConnResult.PinWrong && tail?.result?.ok != true -> RouteProblem.WrongMac
            local != null && tail != null -> RouteProblem.Both
            local != null -> RouteProblem.LocalOnly
            tail != null -> RouteProblem.TailnetOnly
            else -> null
        }
    }
}

// ─── The Android router ─────────────────────────────────────────────────────

/**
 * Chooses the route for one paired Mac and keeps it current, Local first, always. A probe round
 * tries every route at once (the Mac's local addresses with the pinned client, the tailnet through
 * the built-in node, the base URL as it is) and settles as [RoundJudge] says: on Local whenever it
 * answers. Rounds run before every attempt to connect ([prepare], joining one under way), on every
 * change of network (the default network, its kind, its addresses), when the built-in node starts
 * or stops, when the Mac reports new addresses, and now and then while not on Local with local
 * addresses worth trying ([RecheckBackoff]: every 30 s to 2 minutes in the same subnet as the Mac,
 * 2 to 30 minutes elsewhere). [onRoute] hears every change of route a round makes by itself (the
 * hub reconnects through it). Registered in [ActiveRoutes], so every [Api] for this base follows
 * along. What it sees and decides goes to [ConnLog].
 */
class LanRouter(
    context: Context,
    private val scope: CoroutineScope,
    private val pairing: Pairing,
    private val certs: DeviceCertStore,
    private val onRoute: (NetRoute) -> Unit,
) {
    private val app = context.applicationContext
    private val connectivity = app.getSystemService(ConnectivityManager::class.java)
    /** The computer on the tailnet, as the pairing names it (null: the pairing says nothing about one). */
    private val tailnet = TailnetTarget.of(pairing)
    private val chooser = RouteChooser(pairing.baseUrl, pairing.lanPort, tailnet)

    /** The Mac's latest word on its listener; null until a snapshot says (then the pairing link's addresses serve). */
    var lan: LanInfo? = null
        set(v) {
            val changed = v?.addresses != field?.addresses || v?.fingerprint != field?.fingerprint || v?.port != field?.port
            field = v
            if (changed && !closed) {
                ConnLog.add(
                    ConnKind.Mac, ConnResult.Info, RouteKind.Local,
                    text = if (v == null) "the Mac's local listener is off" else "the Mac is at ${v.addresses.take(3).joinToString(", ").ifEmpty { "no local address" }} on port ${v.port}",
                )
                recheck("the Mac's local addresses")
            }
        }

    var route by mutableStateOf(NetRoute.remote(pairing.baseUrl))
        private set
    val kind: RouteKind get() = route.kind

    /** The last round's story (what was tried, how each route answered): the offline card words its problem from it. */
    var report by mutableStateOf<RouteReport?>(null)
        private set

    /** A probe round: [decided] completes with its report once it settles (null: it gave way to a newer round). */
    private class Round(val reason: String) {
        val decided = CompletableDeferred<RouteReport?>()
        var job: Job? = null
    }

    // Rounds, decisions and failures are on the main thread (the hub's scope).
    private var round: Round? = null
    private var decidedAt = Long.MIN_VALUE / 2
    private var failedAt = Long.MIN_VALUE / 2
    @Volatile private var ticker: Job? = null
    private var closed = false
    /** Stops hearing the built-in node. */
    private var unwatchNode: (() -> Unit)? = null
    /** The client through the built-in node, for the proxy (port and secret) it was built for. */
    private var viaNode: Pair<String, OkHttpClient>? = null
    /** The clients built for the current pin and device certificate (rebuilt when either changes). */
    private var pinned: Pinned? = null

    private class Pinned(val fingerprint: String, val identity: DeviceIdentity?, val client: OkHttpClient) {
        /** The hotspot sweep's own ([PinnedTls.sweep]). */
        val sweep: OkHttpClient by lazy { PinnedTls.sweep(client) }
    }

    /**
     * Hears the default network come, go, become another kind (Wi-Fi to mobile, a VPN over it) or
     * get other addresses (another Wi-Fi's subnet). Capabilities follow every onAvailable, so they
     * are the one signal for a network's arrival; signal strength and the like change all the time
     * and aren't news, hence the key. Each change is a round at once, Local first.
     */
    private val watch = object : ConnectivityManager.NetworkCallback() {
        private var key: Any? = null
        private var addrsOf: Network? = null
        private var addrs: List<String>? = null
        override fun onLost(network: Network) { changed(listOf("down", network), "network lost") }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            changed(listOf(network, TRANSPORTS_WATCHED.filter(caps::hasTransport), caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)), "the network changed")
        }
        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            val a = lp.linkAddresses.map { it.toString() }.sorted()
            // The same network with other addresses (not its first ones arriving): another subnet, say.
            val again = addrsOf == network && addrs?.isNotEmpty() == true && addrs != a
            addrsOf = network
            addrs = a
            if (again) scope.launch { recheck("the phone's addresses changed"); tick() }
        }
        private fun changed(k: Any, why: String) {
            if (k == key) return
            key = k
            scope.launch { recheck(why); tick() }
        }
    }

    fun start() {
        ActiveRoutes.register(pairing.baseUrl, this)
        // The built-in node coming up (or going) is a reason to look again, like a network change.
        if (tailnet != null) {
            var last: String? = null
            unwatchNode = Tsnet.watch { s ->
                val k = "${s.state}/${s.running}"
                if (k != last) {
                    last = k
                    ConnLog.add(ConnKind.Node, if (s.running) ConnResult.Ok else ConnResult.Info, RouteKind.Tailscale, text = "the built-in node is ${nodeState(s)}${s.error?.let { ": $it" } ?: ""}")
                    recheck("the built-in node is ${nodeState(s)}")
                }
            }
        }
        // The watch reports the current network at once, which is the first probe round; without
        // one (no network) a round says so.
        if (runCatching { connectivity?.registerDefaultNetworkCallback(watch) }.isFailure) recheck("start")
        tick()
    }

    /**
     * (Re)starts the periodic check from the start: at start and on every network change. Every
     * 30 s it looks at the network (cheap, no probe); the re-check itself backs off ([RecheckBackoff]).
     * On mobile data alone it finds nothing worth trying.
     */
    private fun tick() {
        if (closed) return
        ticker?.cancel()
        ticker = scope.launch {
            val backoff = RecheckBackoff(elapsed())
            while (isActive) {
                delay(RoutePolicy.TICK_MS)
                if (chooser.kind == RouteKind.Local) continue
                val (net, gateways, look) = withContext(Dispatchers.IO) { Triple(netKind(), hotspotGateways(), connectivity?.activeNetwork to phoneSubnets()) }
                val known = knownAddresses()
                val near = net == NetKind.Wifi && RoutePolicy.sameSubnet(look.second, chooser.known(known))
                if (backoff.due(elapsed(), gateways, look.first, near) && chooser.wantsRecheck(net, gateways.isNotEmpty(), known, gateways, Tsnet.status.running)) {
                    recheck(if (near) "looking for Local again (same subnet as the Mac)" else "periodic re-check")
                }
            }
        }
    }

    fun close() {
        closed = true
        ActiveRoutes.unregister(pairing.baseUrl, this)
        unwatchNode?.invoke()
        runCatching { connectivity?.unregisterNetworkCallback(watch) }
        round?.job?.cancel(); ticker?.cancel()
    }

    /**
     * A request over [kind] failed in use (the snapshot, the socket): the route falls back to the
     * base URL until the next round, which the hub's next attempt runs, Local first ([prepare]). A
     * route that keeps failing is tried after the others for a while ([RouteChooser.failedInUse]),
     * that route only: the tailnet failing never holds Local back. Not announced through [onRoute]:
     * the caller is handling the failure (and its retry).
     */
    fun failed(kind: RouteKind) {
        val now = elapsed()
        failedAt = now
        val hold = chooser.failedInUse(kind, now)
        if (hold > 0) ConnLog.add(ConnKind.Wait, ConnResult.Info, kind, text = "failed again within minutes: tried after the other routes for ${hold / 1000}s")
        if (chooser.kind != RouteKind.Remote) {
            chooser.localFailed()
            publish(notify = false)
        }
    }

    /** [kind] answers but can't be used for now ([why]): tried after the other routes for [ms]. */
    fun hold(kind: RouteKind, ms: Long, why: String) {
        val now = elapsed()
        chooser.hold(kind, now + ms)
        failedAt = now
        ConnLog.add(ConnKind.Wait, ConnResult.Info, kind, text = "$why: tried after the other routes for ${ms / 1000}s")
        if (chooser.kind == kind && kind != RouteKind.Remote) {
            chooser.localFailed()
            publish(notify = false)
        }
    }

    /**
     * The device certificate changed (just issued, or dropped). On the local route the pinned
     * client is swapped in place, so the request under way carries on with the new identity; on
     * the remote one the local addresses are tried again with it.
     */
    fun identityChanged() {
        pinned = null
        if (chooser.kind == RouteKind.Local) publish(notify = false) else recheck("a new device certificate")
    }

    private fun fingerprint(): String? = lan?.fingerprint ?: pairing.fingerprint
    private val port: Int get() = lan?.port ?: pairing.lanPort
    private fun knownAddresses(): List<String> = (lan?.addresses ?: emptyList()) + pairing.lanAddresses

    private fun pinnedClient(): Pinned? {
        val fp = fingerprint() ?: return null
        val have = pinned
        if (have != null && have.fingerprint == fp) return have
        val identity = certs.identity()
        return Pinned(fp, identity, PinnedTls.client(fp, identity)).also { pinned = it }
    }

    /**
     * The client through the built-in node's proxy, while the node runs: rebuilt when the proxy's
     * port changes (the node restarted). The proxy is told the computer's name and port, which is
     * all it will tunnel to.
     */
    private fun nodeClient(): OkHttpClient? {
        val t = tailnet ?: return null
        val node = Tsnet.status.takeIf { it.running } ?: return null
        // The node must be the one for this pairing's control server.
        if (!Tsnet.serves(pairing.controlUrl)) return null
        // The allowlist is set every time (a pairing under way may have added to it), the client kept per proxy (port and secret).
        t.hostPort?.let { Tsnet.setAllowed(listOf(it)) }
        val key = "${node.proxyPort}/${node.proxyToken}"
        viaNode?.takeIf { it.first == key }?.let { return it.second }
        val fp = t.fingerprint ?: fingerprint()
        return TsnetTls.client(t.base, node.proxyPort, node.proxyToken, fp, certs.identity()).also { viaNode = key to it }
    }

    /** A round now, replacing one under way ([reason] goes to the log). */
    fun recheck(reason: String = "re-check") {
        if (!closed) startRound(reason)
    }

    /**
     * The route for an attempt to connect: what a round settled on moments ago ([RoutePolicy.FRESH_MS],
     * with no failure since), else the round under way, else a new one: Local first, always. The
     * report says what was tried; its winner is null when nothing answered.
     */
    suspend fun prepare(reason: String): RouteReport {
        repeat(MAX_JOINS) {
            if (closed) throw CancellationException("router closed")
            val rep = report
            if (rep?.winner != null && elapsed() - decidedAt < RoutePolicy.FRESH_MS && decidedAt > failedAt) return rep
            val cur = round
            val r = if (cur != null && cur.job?.isActive == true && !cur.decided.isCompleted) cur else startRound(reason)
            r.decided.await()?.let { return it }
            // That round gave way to a newer one (the network changed, say): wait for the newer.
            currentCoroutineContext().ensureActive()
        }
        return report ?: RouteReport(System.currentTimeMillis(), NetKind.None, false, emptyList(), null)
    }

    private fun startRound(reason: String): Round {
        val old = round
        val r = Round(reason)
        round = r
        old?.job?.cancel()
        r.job = scope.launch {
            try {
                runRound(r)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                ConnLog.add(ConnKind.Route, ConnResult.Failed, text = "the round stopped: ${e.javaClass.simpleName}")
                if (round === r) r.decided.complete(RouteReport(System.currentTimeMillis(), NetKind.None, false, emptyList(), null))
            } finally {
                r.decided.complete(null)
            }
        }
        return r
    }

    private class Env(val pin: Pinned?, val net: NetKind, val gateways: List<String>, val subnets: List<Pair<String, Int>>, val words: String)

    /** One handshake's outcome. */
    private class Probed(val result: ConnResult, val detail: String?, val ms: Long)

    /** Tries every route at once and settles as [RoundJudge] says; every answer and the choice go to the log. */
    private suspend fun runRound(r: Round) {
        val t0 = elapsed()
        // The key store and the interfaces are read off the main thread.
        val env = withContext(Dispatchers.IO) { Env(pinnedClient(), netKind(), hotspotGateways(), phoneSubnets(), netWords()) }
        val known = chooser.known(knownAddresses())
        val hotspot = env.gateways.isNotEmpty()
        val near = env.net == NetKind.Wifi && RoutePolicy.sameSubnet(env.subnets, known)
        val p = port
        ConnLog.add(ConnKind.Network, ConnResult.Info, text = buildString {
            append(r.reason)
            append(": ")
            append(env.words)
            if (near) append(", same subnet as the Mac")
            if (hotspot) append(", hosting a hotspot")
        })
        val tries = mutableListOf<RouteTry>()
        fun skip(k: RouteKind, why: String) {
            tries += RouteTry(k, ConnResult.Skipped, why = why)
            ConnLog.add(ConnKind.Probe, ConnResult.Skipped, k, text = why)
        }
        val candidates = if (env.pin != null && RoutePolicy.shouldProbe(env.net, hotspot)) RoutePolicy.candidates(known, env.gateways) else emptyList()
        when {
            env.pin == null -> skip(RouteKind.Local, "no certificate pin from the Mac yet")
            env.net == NetKind.None && !hotspot -> skip(RouteKind.Local, "no network")
            !RoutePolicy.shouldProbe(env.net, hotspot) -> skip(RouteKind.Local, "on mobile data: the Mac can't be next door")
            candidates.isEmpty() -> skip(RouteKind.Local, "no local address known")
        }
        val target = tailnet
        val node = if (target != null) withContext(Dispatchers.IO) { nodeClient() } else null
        if (target != null && node == null) {
            skip(
                RouteKind.Tailscale,
                when {
                    !Tsnet.available -> "no built-in Tailscale in this build"
                    Tsnet.status.running && !Tsnet.serves(pairing.controlUrl) -> "the built-in node serves another control server"
                    else -> "the built-in node is ${nodeState(Tsnet.status)}"
                },
            )
        }
        val judge = RoundJudge(waitForLocal = near || hotspot, demoted = chooser.demoted(t0))
        val results = Channel<RouteTry>(Channel.UNLIMITED)
        val pending = mutableSetOf<RouteKind>()
        var localWinner: String? = null
        var settled: RouteKind? = null
        coroutineScope {
            val pin = env.pin
            if (pin != null && candidates.isNotEmpty()) {
                pending += RouteKind.Local
                launch { results.send(local(pin, candidates, known, p) { localWinner = it }) }
            }
            if (node != null && target != null) {
                pending += RouteKind.Tailscale
                launch { results.send(throughNode(node, target.base)) }
            }
            pending += RouteKind.Remote
            launch { results.send(asIs(pairing.baseUrl)) }
            while (pending.isNotEmpty()) {
                val t = results.receive()
                pending -= t.route
                tries += t
                val current = settled
                if (current == null) {
                    val pick = judge.settle(tries.filter { it.result.ok }.map { it.route }.toSet(), pending) ?: continue
                    settled = pick
                    decide(r, pick, localWinner, p, tries, env.net, near, t0, upgrade = false)
                    if (!judge.mayImprove(pick, pending)) break
                } else if (t.result.ok && judge.upgrade(current, t.route)) {
                    settled = t.route
                    decide(r, t.route, localWinner, p, tries, env.net, near, t0, upgrade = true)
                    break
                }
            }
            // The rest aren't needed (the base URL once Local answered, say).
            coroutineContext.cancelChildren()
        }
        if (settled == null) decide(r, null, null, p, tries, env.net, near, t0, upgrade = false)
    }

    private fun decide(r: Round, pick: RouteKind?, localWinner: String?, port: Int, tries: List<RouteTry>, net: NetKind, near: Boolean, t0: Long, upgrade: Boolean) {
        if (round !== r || closed) return
        chooser.settle(if (pick == RouteKind.Local) localWinner else null, tailscale = pick == RouteKind.Tailscale, lanPort = port)
        val rep = RouteReport(System.currentTimeMillis(), net, near, tries.toList(), pick)
        report = rep
        decidedAt = elapsed()
        ConnLog.add(
            ConnKind.Route, if (pick != null) ConnResult.Ok else ConnResult.Failed, pick ?: RouteKind.Remote,
            target = ConnScrub.hostPort(chooser.base), text = RouteWords.summary(rep, upgrade), ms = elapsed() - t0,
        )
        publish()
        r.decided.complete(rep)
    }

    /** The Mac's local addresses (and a hotspot's), Local's way: the first good handshake wins. */
    private suspend fun local(pin: Pinned, candidates: List<String>, known: List<String>, port: Int, won: (String) -> Unit): RouteTry {
        val named = known.map { it.trim() }.toSet()
        val seen = ConcurrentHashMap<String, Probed>()
        val winner = RoutePolicy.choose(candidates) { addr ->
            val base = RoutePolicy.baseOf(addr, port)
            val mine = addr in named
            val res = probe(if (mine) pin.client else pin.sweep, base)
            seen[addr] = res
            // A hotspot sweep's hundreds of silences aren't news one by one; what answers is.
            if (mine || res.result.ok) ConnLog.add(ConnKind.Probe, res.result, RouteKind.Local, ConnScrub.hostPort(base), res.detail ?: if (!mine) "on this phone's hotspot" else null, res.ms)
            res.result.ok
        }
        if (winner != null) {
            won(winner)
            return RouteTry(RouteKind.Local, ConnResult.Ok, ConnScrub.hostPort(RoutePolicy.baseOf(winner, port)), seen[winner]?.ms)
        }
        // Known addresses that never said a word ran out of time.
        for (a in candidates.filter { it in named && !seen.containsKey(it) }) {
            seen[a] = Probed(ConnResult.Timeout, null, RoutePolicy.PROBE_TIMEOUT_MS)
            ConnLog.add(ConnKind.Probe, ConnResult.Timeout, RouteKind.Local, ConnScrub.hostPort(RoutePolicy.baseOf(a, port)), "no answer in ${RoutePolicy.PROBE_TIMEOUT_MS / 1000}s", RoutePolicy.PROBE_TIMEOUT_MS)
        }
        val swept = candidates.count { it !in named }
        if (swept > 0) ConnLog.add(ConnKind.Probe, ConnResult.Timeout, RouteKind.Local, text = "hotspot sweep: $swept addresses, none answered")
        val mine = seen.filterKeys { it in named }
        val worst = RoutePolicy.worst(mine.values.map { it.result }) ?: ConnResult.Timeout
        val at = mine.entries.firstOrNull { it.value.result == worst }
        return RouteTry(RouteKind.Local, worst, at?.key?.let { ConnScrub.hostPort(RoutePolicy.baseOf(it, port)) }, at?.value?.ms, at?.value?.detail)
    }

    /** The computer on the tailnet through the built-in node's proxy. */
    private suspend fun throughNode(node: OkHttpClient, base: String): RouteTry {
        val t0 = elapsed()
        val res = withTimeoutOrNull(RoutePolicy.NODE_PROBE_MS) { probe(node, base) }
            ?: Probed(ConnResult.Timeout, "no answer in ${RoutePolicy.NODE_PROBE_MS / 1000}s", elapsed() - t0)
        ConnLog.add(ConnKind.Probe, res.result, RouteKind.Tailscale, ConnScrub.hostPort(base), listOfNotNull("through the built-in node", res.detail).joinToString(": "), res.ms)
        return RouteTry(RouteKind.Tailscale, res.result, ConnScrub.hostPort(base), res.ms, res.detail)
    }

    /** The paired base URL as it is (the Tailscale app on this phone, or an address on the internet). */
    private suspend fun asIs(base: String): RouteTry {
        val t0 = elapsed()
        val res = withTimeoutOrNull(RoutePolicy.BASE_PROBE_MS) { probe(Net.client, base) }
            ?: Probed(ConnResult.Timeout, "no answer in ${RoutePolicy.BASE_PROBE_MS / 1000}s", elapsed() - t0)
        ConnLog.add(ConnKind.Probe, res.result, RouteKind.Remote, ConnScrub.hostPort(base), listOfNotNull("the base URL as it is", res.detail).joinToString(": "), res.ms)
        return RouteTry(RouteKind.Remote, res.result, ConnScrub.hostPort(base), res.ms, res.detail)
    }

    private fun publish(notify: Boolean = true) {
        val pin = if (chooser.kind == RouteKind.Local) pinnedClient() else null
        val node = if (chooser.kind == RouteKind.Tailscale) nodeClient() else null
        val next = when {
            chooser.kind == RouteKind.Local && pin != null -> NetRoute(chooser.base, RouteKind.Local, pin.client, pin.fingerprint, pin.identity)
            chooser.kind == RouteKind.Tailscale && node != null -> NetRoute(chooser.base, RouteKind.Tailscale, node, tailnet?.fingerprint, certs.identity())
            else -> NetRoute.remote(pairing.baseUrl)
        }
        if (next.base == route.base && next.kind == route.kind && next.client === route.client) return
        route = next
        if (notify) onRoute(next)
    }

    /**
     * One handshake and `GET /v1/health`: [ConnResult.Ok] when the server (the pinned one, on the
     * local route) answered. Asynchronous, so a losing probe is cut short the moment another wins
     * (OkHttp's cancel closes its socket; a blocking connect would hold the round up until its own
     * timeout); one cut short says nothing.
     */
    private suspend fun probe(client: OkHttpClient, base: String): Probed = suspendCancellableCoroutine { cont ->
        val t0 = elapsed()
        val call = client.newCall(Request.Builder().url("$base/v1/health").build())
        cont.invokeOnCancellation { call.cancel() }
        call.enqueue(object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (call.isCanceled()) return
                val (result, detail) = RoutePolicy.classify(e)
                if (cont.isActive) cont.resume(Probed(result, detail, elapsed() - t0))
            }
            override fun onResponse(call: Call, response: Response) {
                val code = response.use { it.code }
                val ok = code in 200..299
                if (cont.isActive) cont.resume(Probed(if (ok) ConnResult.Ok else ConnResult.Http, if (ok) null else "HTTP $code", elapsed() - t0))
            }
        })
    }

    private fun netKind(): NetKind {
        val cm = connectivity ?: return NetKind.None
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return NetKind.None
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetKind.Wifi
            // A VPN over whatever carries it, mobile data included: a VPN into the Mac's own network
            // (WireGuard, UniFi) reaches its local addresses, so the local route is worth probing.
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> NetKind.Wifi
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetKind.Mobile
            else -> NetKind.None
        }
    }

    /** The default network in a few words, for the log: "Wi-Fi", "VPN over mobile data, not validated". */
    private fun netWords(): String {
        val cm = connectivity ?: return "no network"
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return "no network"
        return capsWords(caps)
    }

    companion object {
        private val TRANSPORTS_WATCHED = listOf(NetworkCapabilities.TRANSPORT_WIFI, NetworkCapabilities.TRANSPORT_CELLULAR, NetworkCapabilities.TRANSPORT_ETHERNET, NetworkCapabilities.TRANSPORT_VPN)
        /** How many newer rounds an attempt to connect follows before it takes what it has. */
        private const val MAX_JOINS = 20

        private fun elapsed(): Long = android.os.SystemClock.elapsedRealtime()

        private fun capsWords(caps: NetworkCapabilities): String {
            val under = listOfNotNull(
                "Wi-Fi".takeIf { caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) },
                "Ethernet".takeIf { caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) },
                "mobile data".takeIf { caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) },
            ).joinToString(" and ").ifEmpty { "a network" }
            val vpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            return (if (vpn) "a VPN over $under" else under) + if (validated) "" else ", not validated yet"
        }

        /** The built-in node's state in the log's words. */
        fun nodeState(s: TsnetStatus): String = when {
            s.running -> "running"
            s.needsLogin -> "signed out (NeedsLogin)"
            s.needsApproval -> "waiting for approval"
            s.state == "Running" -> "joining (no proxy yet)"
            else -> s.state.lowercase()
        }

        /** This phone's IPv4 addresses with their prefix lengths (Wi-Fi's, a hotspot's), for [RoutePolicy.sameSubnet]. */
        fun phoneSubnets(): List<Pair<String, Int>> = runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { runCatching { it.isUp && !it.isLoopback }.getOrDefault(false) }
                .flatMap { it.interfaceAddresses.orEmpty() }
                .filter { it.address is Inet4Address && it.address.isSiteLocalAddress }
                .mapNotNull { a -> a.address.hostAddress?.let { it to a.networkPrefixLength.toInt() } }
        }.getOrDefault(emptyList())

        /**
         * The IPv4 gateways of the hotspots this phone hosts: an up interface (not loopback) with a
         * private address ending in `.1`, which is what Android gives the phone's own side of a
         * hotspot or USB tether. Android has no public "is my hotspot on" API, so the interfaces say.
         */
        fun hotspotGateways(): List<String> = runCatching {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
                .filter { runCatching { it.isUp && !it.isLoopback }.getOrDefault(false) }
                .flatMap { it.inetAddresses.toList() }
                .filterIsInstance<Inet4Address>()
                .filter { it.isSiteLocalAddress && it.address.last() == 1.toByte() }
                .map { it.hostAddress ?: "" }
                .filter { it.isNotEmpty() }
        }.getOrDefault(emptyList())
    }
}
