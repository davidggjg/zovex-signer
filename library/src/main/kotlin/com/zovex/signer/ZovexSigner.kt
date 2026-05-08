package com.zovex.signer

import com.android.apksig.ApkSigner
import org.spongycastle.asn1.x500.X500Name
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter
import org.spongycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.spongycastle.jce.provider.BouncyCastleProvider
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.security.*
import java.security.cert.X509Certificate
import java.util.Date

object ZovexSigner {

    private const val KS_ALIAS = "zovex"
    private const val KS_PASS  = "zovex2024"
    private const val SC       = "SC"

    private val provider: Provider by lazy {
        Security.getProvider(SC)
            ?: BouncyCastleProvider().also { Security.insertProviderAt(it, 1) }
    }

    fun sign(
        unsigned: File,
        out: File,
        keystoreStream: InputStream? = null,
        keystoreOut: OutputStream? = null
    ) {
        provider // init
        val (key, cert) = if (keystoreStream != null) {
            loadKeyPair(keystoreStream)
        } else {
            val pair = createKeyPair()
            if (keystoreOut != null) saveKeyPair(pair.first, pair.second, keystoreOut)
            pair
        }

        ApkSigner.Builder(listOf(
            ApkSigner.SignerConfig.Builder("CERT", key, listOf(cert)).build()
        ))
            .setInputApk(unsigned)
            .setOutputApk(out)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setMinSdkVersion(26)
            .build()
            .sign()
    }

    fun createKeyPair(): Pair<PrivateKey, X509Certificate> {
        val kpg = KeyPairGenerator.getInstance("RSA", provider)
        kpg.initialize(2048, SecureRandom())
        val kp  = kpg.generateKeyPair()
        val now = System.currentTimeMillis()
        val sub = X500Name("CN=ZovexInjector, O=Zovex, C=IL")
        val cert = JcaX509CertificateConverter().setProvider(provider)
            .getCertificate(
                JcaX509v3CertificateBuilder(
                    sub, BigInteger.valueOf(now),
                    Date(now - 86400_000L),
                    Date(now + 3650L * 86400_000L),
                    sub, kp.public
                ).build(JcaContentSignerBuilder("SHA256withRSA").setProvider(provider).build(kp.private))
            )
        return Pair(kp.private, cert)
    }

    fun saveKeyPair(key: PrivateKey, cert: X509Certificate, out: OutputStream) {
        val ks = KeyStore.getInstance("BKS", provider).also { it.load(null) }
        ks.setKeyEntry(KS_ALIAS, key, KS_PASS.toCharArray(), arrayOf(cert))
        ks.store(out, KS_PASS.toCharArray())
    }

    fun loadKeyPair(input: InputStream): Pair<PrivateKey, X509Certificate> {
        val ks = KeyStore.getInstance("BKS", provider).also {
            it.load(input, KS_PASS.toCharArray())
        }
        return Pair(
            ks.getKey(KS_ALIAS, KS_PASS.toCharArray()) as PrivateKey,
            ks.getCertificate(KS_ALIAS) as X509Certificate
        )
    }
}
