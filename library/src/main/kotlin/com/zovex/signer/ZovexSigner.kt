package com.zovex.signer

import com.android.apksig.ApkSigner
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
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

    init {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }

    fun sign(
        unsigned: File,
        out: File,
        keystoreStream: InputStream? = null,
        keystoreOut: OutputStream? = null
    ) {
        val (key, cert) = if (keystoreStream != null) {
            loadKeyPair(keystoreStream)
        } else {
            val pair = createKeyPair()
            if (keystoreOut != null) saveKeyPair(pair.first, pair.second, keystoreOut)
            pair
        }

        val signerConfig = ApkSigner.SignerConfig.Builder(
            "CERT", key, listOf(cert)
        ).build()

        ApkSigner.Builder(listOf(signerConfig))
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
        val kpg = KeyPairGenerator.getInstance("RSA", "BC")
        kpg.initialize(2048, SecureRandom())
        val kp = kpg.generateKeyPair()
        val now     = System.currentTimeMillis()
        val subject = X500Name("CN=ZovexInjector, O=Zovex, C=IL")
        val certHolder = JcaX509v3CertificateBuilder(
            subject, BigInteger.valueOf(now),
            Date(now - 86400_000L),
            Date(now + 3650L * 86400_000L),
            subject, kp.public
        ).build(JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(kp.private))
        val cert = JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder)
        return Pair(kp.private, cert)
    }

    fun saveKeyPair(key: PrivateKey, cert: X509Certificate, out: OutputStream) {
        val ks = KeyStore.getInstance("BKS", "BC").also { it.load(null) }
        ks.setKeyEntry(KS_ALIAS, key, KS_PASS.toCharArray(), arrayOf(cert))
        ks.store(out, KS_PASS.toCharArray())
    }

    fun loadKeyPair(input: InputStream): Pair<PrivateKey, X509Certificate> {
        val ks = KeyStore.getInstance("BKS", "BC").also {
            it.load(input, KS_PASS.toCharArray())
        }
        return Pair(
            ks.getKey(KS_ALIAS, KS_PASS.toCharArray()) as PrivateKey,
            ks.getCertificate(KS_ALIAS) as X509Certificate
        )
    }
}
