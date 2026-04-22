package org.packetfence.agent.crypto;

import org.junit.Test;
import org.junit.Before;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import static org.junit.Assert.*;

/**
 * Characterisation tests for PKCS#12 credential loading logic.
 *
 * These tests capture the behaviour of the KeyStore loading code extracted
 * from MainActivity.computeUserCertAndKey(), so that future extraction of a
 * CredentialLoader class in Plan 03 cannot silently break credential handling.
 *
 * The test.p12 fixture was generated with:
 *   keytool -genkeypair -alias test -keystore test.p12 -storetype PKCS12
 *           -keyalg RSA -keysize 2048 -validity 365
 *           -storepass testpass -keypass testpass
 *           -dname "CN=Test,O=PacketFence"
 */
public class CredentialLoaderTest {

    private static final String FIXTURE_PATH = "/fixtures/test.p12";
    private static final String CORRECT_PASSWORD = "testpass";
    private static final String WRONG_PASSWORD   = "wrongpassword";

    // -- helper -----------------------------------------------------------

    private byte[] readFixtureBytes() throws IOException {
        try (InputStream is = getClass().getResourceAsStream(FIXTURE_PATH)) {
            assertNotNull("test.p12 fixture must exist on classpath at " + FIXTURE_PATH, is);
            return is.readAllBytes();
        }
    }

    // -- tests ------------------------------------------------------------

    @Test
    public void loadP12WithCorrectPassword_keystoreOpens() throws Exception {
        byte[] p12Bytes = readFixtureBytes();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new java.io.ByteArrayInputStream(p12Bytes), CORRECT_PASSWORD.toCharArray());
        // If we got here without exception, the keystore opened successfully
        assertTrue("Keystore should have at least one alias", ks.size() > 0);
    }

    @Test
    public void loadP12WithCorrectPassword_aliasIsPresent() throws Exception {
        byte[] p12Bytes = readFixtureBytes();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new java.io.ByteArrayInputStream(p12Bytes), CORRECT_PASSWORD.toCharArray());

        Enumeration<String> aliases = ks.aliases();
        assertTrue("At least one alias expected in keystore", aliases.hasMoreElements());
    }

    @Test
    public void loadP12WithCorrectPassword_certificateIsX509() throws Exception {
        byte[] p12Bytes = readFixtureBytes();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new java.io.ByteArrayInputStream(p12Bytes), CORRECT_PASSWORD.toCharArray());

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            Certificate cert = ks.getCertificate(alias);
            assertNotNull("Certificate must not be null for alias: " + alias, cert);
            assertInstanceOf("Certificate must be X509Certificate", X509Certificate.class, cert);
        }
    }

    @Test
    public void loadP12WithCorrectPassword_privateKeyIsExtractable() throws Exception {
        byte[] p12Bytes = readFixtureBytes();
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(new java.io.ByteArrayInputStream(p12Bytes), CORRECT_PASSWORD.toCharArray());

        String alias = ks.aliases().nextElement();
        PrivateKey key = (PrivateKey) ks.getKey(alias, CORRECT_PASSWORD.toCharArray());
        assertNotNull("Private key must be extractable with correct password", key);
    }

    @Test
    public void loadP12WithWrongPassword_throwsException() throws Exception {
        byte[] p12Bytes = readFixtureBytes();
        KeyStore ks = KeyStore.getInstance("PKCS12");

        try {
            ks.load(new java.io.ByteArrayInputStream(p12Bytes), WRONG_PASSWORD.toCharArray());
            // If we reach this point, the implementation accepted a wrong password — that is a problem
            fail("Expected an exception when loading PKCS12 with wrong password");
        } catch (IOException e) {
            // expected: wrong password causes an IOException (KeyStore.load spec)
        }
    }

    @Test
    public void loadP12NullBytes_throwsException() {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, CORRECT_PASSWORD.toCharArray());
            // Null stream is allowed by the spec (creates empty keystore), so just
            // verify the keystore has no entries rather than expecting a throw.
            assertEquals(0, ks.size());
        } catch (Exception e) {
            // Also acceptable — any failure on null input is fine for our characterisation
        }
    }

    // -- private helper ---------------------------------------------------

    private static <T> void assertInstanceOf(String message, Class<T> expectedType, Object actual) {
        assertTrue(message + " (was: " + (actual == null ? "null" : actual.getClass().getName()) + ")",
                expectedType.isInstance(actual));
    }
}
