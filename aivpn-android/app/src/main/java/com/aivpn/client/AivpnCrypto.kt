package com.aivpn.client

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AIVPN protocol crypto engine (pure Kotlin, no JNI).
 *
 * Implements a simplified version of the AIVPN wire protocol:
 *   - X25519 key exchange (via platform KeyAgreement or bundled Curve25519)
 *   - ChaCha20-Poly1305 AEAD encryption
 *   - Resonance tag generation for session identification
 *   - PFS key ratchet on ServerHello
 *
 * Wire format: TAG(8) | MDH(4) | encrypt(pad_len_u16 || inner_payload || padding)
 */
class AivpnCrypto(private val serverStaticPub: ByteArray) {

    // Constants matching the Rust implementation
    companion object {
        const val TAG_SIZE = 8
        const val MDH_SIZE = 4
        const val NONCE_SIZE = 12
        const val KEY_SIZE = 32
        const val INNER_HEADER_SIZE = 4
        val FIELD_P: BigInteger = BigInteger.ONE.shiftLeft(255) - BigInteger.valueOf(19)
        val A24: BigInteger = BigInteger.valueOf(121665)
        val BI_TWO: BigInteger = BigInteger.valueOf(2)
    }

    private val rng = SecureRandom()

    // Client ephemeral keypair (X25519)
    private val clientPrivate = ByteArray(32).also { rng.nextBytes(it) }
    private val clientPublic: ByteArray

    // Session keys derived from DH
    private var sessionKey = ByteArray(KEY_SIZE)
    private var tagSecret = ByteArray(KEY_SIZE)

    // Monotonic counters
    private var sendCounter: Long = 0
    private var recvCounter: Long = 0
    private var sendSeq: Int = 0

    init {
        // Clamp private key (X25519 convention)
        clientPrivate[0] = (clientPrivate[0].toInt() and 248).toByte()
        clientPrivate[31] = (clientPrivate[31].toInt() and 127).toByte()
        clientPrivate[31] = (clientPrivate[31].toInt() or 64).toByte()

        // Compute public key = clientPrivate * basepoint
        clientPublic = x25519ScalarMultBase(clientPrivate)

        // Derive initial session keys from DH1 = clientPrivate * serverStaticPub
        val sharedSecret = x25519ScalarMult(clientPrivate, serverStaticPub)
        deriveKeys(sharedSecret, clientPublic)
    }

    /**
     * Build the initial handshake packet with obfuscated eph_pub.
     */
    fun buildInitPacket(): ByteArray {
        // Obfuscate eph_pub by XORing with BLAKE3-derived mask (matches Rust obfuscate_eph_pub)
        val mask = Blake3.deriveKey("aivpn-eph-obfuscation-v1", serverStaticPub)
        val obfEphPub = ByteArray(32)
        for (i in 0 until 32) {
            obfEphPub[i] = (clientPublic[i].toInt() xor mask[i].toInt()).toByte()
        }

        // Inner payload: Control Keepalive
        val innerHeader = buildInnerHeader(0x02, sendSeq++) // 0x02 = Control
        val controlPayload = byteArrayOf(0x03) // Keepalive subtype
        val innerPayload = innerHeader + controlPayload

        // Build AIVPN packet with eph_pub included
        return buildPacket(innerPayload, obfEphPub)
    }

    /**
     * Build a post-handshake keepalive control packet.
     */
    fun buildKeepalivePacket(): ByteArray {
        val innerHeader = buildInnerHeader(0x02, sendSeq++) // 0x02 = Control
        val controlPayload = byteArrayOf(0x03) // Keepalive subtype
        val innerPayload = innerHeader + controlPayload
        return buildPacket(innerPayload, null)
    }

    /**
     * Process ServerHello — complete the PFS ratchet.
     * Returns true if the ratchet succeeded.
     */
    fun processServerHello(packet: ByteArray): Boolean {
        return try {
            // Validate tag (try range of counters)
            val tag = packet.copyOfRange(0, TAG_SIZE)
            var validCounter: Long? = null
            val timeWindow = System.currentTimeMillis() / 5_000L

            for (offset in longArrayOf(0, -1, 1)) {
                val tw = timeWindow + offset
                for (c in recvCounter until recvCounter + 256) {
                    val expected = generateTag(tagSecret, c, tw)
                    if (expected.contentEquals(tag)) {
                        validCounter = c
                        break
                    }
                }
                if (validCounter != null) break
            }

            if (validCounter == null) return false

            // Decrypt payload
            val ciphertext = packet.copyOfRange(TAG_SIZE + MDH_SIZE, packet.size)
            val nonce = counterToNonce(validCounter)
            val plaintext = decrypt(sessionKey, nonce, ciphertext) ?: return false

            // Strip padding
            if (plaintext.size < 2) return false
            val padLen = (plaintext[0].toInt() and 0xFF) or ((plaintext[1].toInt() and 0xFF) shl 8)
            val inner = plaintext.copyOfRange(2, plaintext.size - padLen)

            // Parse inner header
            if (inner.size < INNER_HEADER_SIZE) return false
            val innerType = inner[0].toInt() and 0xFF
            if (innerType != 0x02) return false // Must be Control

            val controlData = inner.copyOfRange(INNER_HEADER_SIZE, inner.size)
            if (controlData.isEmpty()) return false
            val subtype = controlData[0].toInt() and 0xFF
            if (subtype != 0x09) return false // ServerHello subtype

            // Extract server_eph_pub (32 bytes) + signature (64 bytes)
            if (controlData.size < 1 + 32) return false
            val serverEphPub = controlData.copyOfRange(1, 33)

            // Compute DH2 = clientPrivate * serverEphPub
            val dh2 = x25519ScalarMult(clientPrivate, serverEphPub)

            // Ratchet keys: derive new keys using DH2 + current session key as PSK
            deriveKeys(dh2, clientPublic, sessionKey)

            // Reset counters for the new epoch
            sendCounter = 0
            recvCounter = 0

            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Encrypt an outbound IP packet into the AIVPN wire format.
     */
    fun encryptDataPacket(ipPacket: ByteArray): ByteArray {
        val innerHeader = buildInnerHeader(0x01, sendSeq++) // 0x01 = Data
        val innerPayload = innerHeader + ipPacket
        return buildPacket(innerPayload, null)
    }

    /**
     * Decrypt an inbound AIVPN packet and return the inner IP packet, or null.
     */
    fun decryptDataPacket(packet: ByteArray): ByteArray? {
        if (packet.size < TAG_SIZE + MDH_SIZE + 16) return null

        // Validate tag
        val tag = packet.copyOfRange(0, TAG_SIZE)
        var validCounter: Long? = null
        val timeWindow = System.currentTimeMillis() / 5_000L

        for (offset in longArrayOf(0, -1, 1)) {
            val tw = timeWindow + offset
            for (c in recvCounter until recvCounter + 256) {
                val expected = generateTag(tagSecret, c, tw)
                if (expected.contentEquals(tag)) {
                    validCounter = c
                    break
                }
            }
            if (validCounter != null) break
        }

        if (validCounter == null) return null

        // Decrypt
        val ciphertext = packet.copyOfRange(TAG_SIZE + MDH_SIZE, packet.size)
        val nonce = counterToNonce(validCounter)
        val plaintext = decrypt(sessionKey, nonce, ciphertext) ?: return null

        // Strip padding
        if (plaintext.size < 2) return null
        val padLen = (plaintext[0].toInt() and 0xFF) or ((plaintext[1].toInt() and 0xFF) shl 8)
        if (2 + padLen > plaintext.size) return null
        val inner = plaintext.copyOfRange(2, plaintext.size - padLen)

        // Parse inner header
        if (inner.size < INNER_HEADER_SIZE) return null
        val innerType = inner[0].toInt() and 0xFF

        recvCounter = validCounter + 1

        return when (innerType) {
            0x01 -> inner.copyOfRange(INNER_HEADER_SIZE, inner.size) // Data → IP packet
            else -> null // Control packets handled separately
        }
    }

    // ──────────── Internal helpers ────────────

    private fun buildPacket(innerPayload: ByteArray, ephPub: ByteArray?): ByteArray {
        // Random padding (8-24 bytes)
        val padLen = 8 + rng.nextInt(16)
        val padding = ByteArray(padLen).also { rng.nextBytes(it) }

        // Padded plaintext: pad_len(u16 LE) || inner_payload || random_padding
        val padded = ByteBuffer.allocate(2 + innerPayload.size + padLen)
        padded.put((padLen and 0xFF).toByte())
        padded.put(((padLen shr 8) and 0xFF).toByte())
        padded.put(innerPayload)
        padded.put(padding)
        val paddedBytes = padded.array()

        // Encrypt
        val counter = sendCounter++
        val nonce = counterToNonce(counter)
        val ciphertext = encrypt(sessionKey, nonce, paddedBytes)

        // Generate resonance tag
        val timeWindow = System.currentTimeMillis() / 5_000L
        val tag = generateTag(tagSecret, counter, timeWindow)

        // MDH (4 zero bytes for MVP)
        val mdh = ByteArray(MDH_SIZE)

        // Assemble: TAG | MDH | [eph_pub] | ciphertext
        val totalSize = TAG_SIZE + MDH_SIZE + (ephPub?.size ?: 0) + ciphertext.size
        val result = ByteBuffer.allocate(totalSize)
        result.put(tag)
        result.put(mdh)
        if (ephPub != null) result.put(ephPub)
        result.put(ciphertext)

        return result.array()
    }

    private fun buildInnerHeader(type: Int, seq: Int): ByteArray {
        return byteArrayOf(
            type.toByte(),
            0x00, // reserved
            (seq and 0xFF).toByte(),
            ((seq shr 8) and 0xFF).toByte()
        )
    }

    private fun counterToNonce(counter: Long): ByteArray {
        val nonce = ByteArray(NONCE_SIZE)
        for (i in 0 until 8) {
            nonce[i] = ((counter shr (i * 8)) and 0xFF).toByte()
        }
        return nonce
    }

    private fun generateTag(secret: ByteArray, counter: Long, timeWindow: Long): ByteArray {
        // BLAKE3 keyed hash: matches Rust generate_resonance_tag
        val counterBytes = ByteArray(8)
        val windowBytes = ByteArray(8)
        for (i in 0 until 8) {
            counterBytes[i] = ((counter shr (i * 8)) and 0xFF).toByte()
            windowBytes[i] = ((timeWindow shr (i * 8)) and 0xFF).toByte()
        }
        val data = counterBytes + windowBytes
        return Blake3.keyedHash(secret, data).copyOf(TAG_SIZE)
    }

    private fun deriveKeys(sharedSecret: ByteArray, clientPub: ByteArray, psk: ByteArray? = null) {
        // Matches Rust derive_session_keys: BLAKE3 derive_key with context strings
        val ikm = if (psk != null) sharedSecret + psk else sharedSecret
        val input = ikm + clientPub
        sessionKey = Blake3.deriveKey("aivpn-session-key-v1", input)
        tagSecret = Blake3.deriveKey("aivpn-tag-secret-v1", input)
    }

    // ──────────── ChaCha20-Poly1305 via Android API ────────────

    private fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val keySpec = SecretKeySpec(key, "ChaCha20")
        val ivSpec = IvParameterSpec(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec)
        return cipher.doFinal(plaintext)
    }

    private fun decrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray): ByteArray? {
        return try {
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            val keySpec = SecretKeySpec(key, "ChaCha20")
            val ivSpec = IvParameterSpec(nonce)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec)
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }

    // ──────────── X25519 scalar multiplication (BigInteger) ────────────

    private fun x25519ScalarMultBase(scalar: ByteArray): ByteArray {
        val basepoint = ByteArray(32).also { it[0] = 9 }
        return x25519ScalarMult(scalar, basepoint)
    }

    private fun x25519ScalarMult(scalar: ByteArray, point: ByteArray): ByteArray {
        val e = scalar.copyOf()
        e[0] = (e[0].toInt() and 248).toByte()
        e[31] = (e[31].toInt() and 127).toByte()
        e[31] = (e[31].toInt() or 64).toByte()

        val u = fromLittleEndian(point.copyOf(32).also { it[31] = (it[31].toInt() and 0x7F).toByte() })

        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = u
        var z3 = BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val bit = (e[t / 8].toInt() ushr (t % 8)) and 1
            swap = swap xor bit
            if (swap != 0) { val tx = x2; x2 = x3; x3 = tx; val tz = z2; z2 = z3; z3 = tz }
            swap = bit

            val a = (x2 + z2).mod(FIELD_P)
            val aa = (a * a).mod(FIELD_P)
            val b = (x2 - z2).mod(FIELD_P)
            val bb = (b * b).mod(FIELD_P)
            val eVal = (aa - bb).mod(FIELD_P)
            val c = (x3 + z3).mod(FIELD_P)
            val d = (x3 - z3).mod(FIELD_P)
            val da = (d * a).mod(FIELD_P)
            val cb = (c * b).mod(FIELD_P)
            x3 = ((da + cb).mod(FIELD_P)).modPow(BI_TWO, FIELD_P)
            z3 = (u * (da - cb).mod(FIELD_P).modPow(BI_TWO, FIELD_P)).mod(FIELD_P)
            x2 = (aa * bb).mod(FIELD_P)
            z2 = (eVal * (aa + A24 * eVal).mod(FIELD_P)).mod(FIELD_P)
        }

        if (swap != 0) { val tx = x2; x2 = x3; x3 = tx; val tz = z2; z2 = z3; z3 = tz }
        return toLittleEndian((x2 * z2.modInverse(FIELD_P)).mod(FIELD_P))
    }

    private fun fromLittleEndian(b: ByteArray): BigInteger {
        val be = b.reversedArray()
        return BigInteger(1, be)
    }

    private fun toLittleEndian(n: BigInteger): ByteArray {
        val be = n.toByteArray()
        val out = ByteArray(32)
        // BigInteger.toByteArray() is big-endian, may have leading zero byte
        val start = if (be.size > 32) be.size - 32 else 0
        val len = minOf(be.size, 32)
        for (i in 0 until len) {
            out[i] = be[be.size - 1 - i]
        }
        return out
    }
}
