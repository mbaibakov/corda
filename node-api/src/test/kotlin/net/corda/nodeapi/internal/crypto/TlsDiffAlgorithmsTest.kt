package net.corda.nodeapi.internal.crypto

import net.corda.core.crypto.newSecureRandom
import net.corda.core.utilities.Try
import net.corda.core.utilities.contextLogger
import net.corda.nodeapi.internal.config.CertificateStore
import net.corda.nodeapi.internal.protonwrapper.netty.init
import org.assertj.core.api.Assertions
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.junit.runners.Parameterized
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import javax.net.ssl.*
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@RunWith(Parameterized::class)
class TlsDiffAlgorithmsTest(private val serverAlgo: String, private val clientAlgo: String,
                            private val cipherSuites: CipherSuites, private val shouldFail: Boolean,
                            private val serverProtocols: TlsProtocols, private val clientProtocols: TlsProtocols) {
    companion object {


        @Parameterized.Parameters(name = "ServerAlgo: {0}, ClientAlgo: {1}, CipherSuites: {2}, Should fail: {3}, ServerProtocols: {4}, ClientProtocols: {5}")
        @JvmStatic
        fun data(): List<Array<Any>> {

            val allAlgos = listOf("ec", "rsa")
            return allAlgos.flatMap {
                serverAlgo -> allAlgos.flatMap {
                    clientAlgo -> listOf(
                        // newServerOldClient
                        arrayOf(serverAlgo, clientAlgo, Companion.CipherSuites.CIPHER_SUITES_ALL, false, Companion.TlsProtocols.BOTH, Companion.TlsProtocols.ONE_2),
                        // oldServerNewClient
                        arrayOf(serverAlgo, clientAlgo, Companion.CipherSuites.CIPHER_SUITES_ALL, false, Companion.TlsProtocols.ONE_2, Companion.TlsProtocols.BOTH),
                        // newServerNewClient
                        arrayOf(serverAlgo, clientAlgo, Companion.CipherSuites.CIPHER_SUITES_ALL, false, Companion.TlsProtocols.BOTH, Companion.TlsProtocols.BOTH)
                    )
                }
            }
        }

        private val logger = contextLogger()

        enum class TlsProtocols(val versions: Array<String>) {
            BOTH(arrayOf("TLSv1.2", "TLSv1.3")),
            ONE_2(arrayOf("TLSv1.2"))
        }

        enum class CipherSuites(val algos: Array<String>) {
            CIPHER_SUITES_ALL(arrayOf(
                    // 1.3 only
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_CHACHA20_POLY1305_SHA256",
                    // 1.2 only
                    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            ))
        }
    }

    @Rule
    @JvmField
    val tempFolder = TemporaryFolder()

    @Test
    fun testClientServerTlsExchange() {

        //System.setProperty("javax.net.debug", "all")

        logger.info("Testing: ServerAlgo: $serverAlgo, ClientAlgo: $clientAlgo, Suites: ${cipherSuites}, Server protocols: $serverProtocols, Client protocols: $clientProtocols, Should fail: $shouldFail")

        val trustStore = CertificateStore.fromResource("net/corda/nodeapi/internal/crypto/keystores/trust.jks", "trustpass", "trustpass")
        val rootCa = trustStore.value.getCertificate("root")

        val serverKeyStore = CertificateStore.fromResource("net/corda/nodeapi/internal/crypto/keystores/float_$serverAlgo.jks", "floatpass", "floatpass")
        val serverCa = serverKeyStore.value.getCertificateAndKeyPair("floatcert", "floatpass")

        val clientKeyStore = CertificateStore.fromResource("net/corda/nodeapi/internal/crypto/keystores/bridge_$clientAlgo.jks", "bridgepass", "bridgepass")
        //val clientCa = clientKeyStore.value.getCertificateAndKeyPair("bridgecert", "bridgepass")

        val serverSocketFactory = createSslContext(serverKeyStore, trustStore).serverSocketFactory
        val clientSocketFactory = createSslContext(clientKeyStore, trustStore).socketFactory

        val serverSocket = (serverSocketFactory.createServerSocket(0) as SSLServerSocket).apply {
            // use 0 to get first free socket
            val serverParams = SSLParameters(cipherSuites.algos, serverProtocols.versions)
            serverParams.wantClientAuth = true
            serverParams.needClientAuth = true
            serverParams.endpointIdentificationAlgorithm = null // Reconfirm default no server name indication, use our own validator.
            sslParameters = serverParams
            useClientMode = false
        }

        val clientSocket = (clientSocketFactory.createSocket() as SSLSocket).apply {
            val clientParams = SSLParameters(cipherSuites.algos, clientProtocols.versions)
            clientParams.endpointIdentificationAlgorithm = null // Reconfirm default no server name indication, use our own validator.
            sslParameters = clientParams
            useClientMode = true
            // We need to specify this explicitly because by default the client binds to 'localhost' and we want it to bind
            // to whatever <hostname> resolves to(as that's what the server binds to). In particular on Debian <hostname>
            // resolves to 127.0.1.1 instead of the external address of the interface, so the ssl handshake fails.
            bind(InetSocketAddress(InetAddress.getLocalHost(), 0))
        }

        val lock = Object()
        var done = false
        var serverError = false

        val testPhrase = "Hello World"
        val serverThread = thread {
            try {
                val sslServerSocket = serverSocket.accept()
                assertTrue(sslServerSocket.isConnected)
                val serverInput = DataInputStream(sslServerSocket.inputStream)
                val receivedString = serverInput.readUTF()
                assertEquals(testPhrase, receivedString)
                synchronized(lock) {
                    done = true
                    lock.notifyAll()
                }
                sslServerSocket.close()
            } catch (ex: Exception) {
                serverError = true
            }
        }

        clientSocket.connect(InetSocketAddress(InetAddress.getLocalHost(), serverSocket.localPort))
        assertTrue(clientSocket.isConnected)

        // Double check hostname manually
        val peerChainTry = Try.on { clientSocket.session.peerCertificates.x509 }
        assertEquals(!shouldFail, peerChainTry.isSuccess, "Unexpected outcome: $peerChainTry")
        when(peerChainTry) {
            is Try.Success -> {
                val peerChain = peerChainTry.getOrThrow()
                val peerX500Principal = peerChain[0].subjectX500Principal
                assertEquals(serverCa.certificate.subjectX500Principal, peerX500Principal)
                X509Utilities.validateCertificateChain(rootCa, peerChain)
                with(DataOutputStream(clientSocket.outputStream)) {
                    writeUTF(testPhrase)
                }
                var timeout = 0
                synchronized(lock) {
                    while (!done) {
                        timeout++
                        if (timeout > 10) throw IOException("Timed out waiting for server to complete")
                        lock.wait(1000)
                    }
                }

                clientSocket.close()
                serverThread.join(1000)
                assertFalse { serverError }
                serverSocket.close()
                assertTrue(done)
            }
            is Try.Failure -> {
                Assertions.assertThatThrownBy {
                    peerChainTry.getOrThrow()
                }.isInstanceOf(SSLPeerUnverifiedException::class.java)

                // Tidy-up in case of failure
                clientSocket.close()
                serverSocket.close()
                serverThread.interrupt()
            }
        }
    }

    private fun createSslContext(keyStore: CertificateStore, trustStore: CertificateStore): SSLContext {
        return SSLContext.getInstance("TLS").apply {
            val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
            keyManagerFactory.init(keyStore)
            val keyManagers = keyManagerFactory.keyManagers
            val trustMgrFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            trustMgrFactory.init(trustStore)
            val trustManagers = trustMgrFactory.trustManagers
            init(keyManagers, trustManagers, newSecureRandom())
        }
    }
}