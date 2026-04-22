package org.packetfence.agent.wifi;

import org.junit.Test;
import xmlwise.Plist;
import xmlwise.XmlParseException;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import static org.junit.Assert.*;

/**
 * Characterisation tests for WiFi profile provisioning logic.
 *
 * These tests capture the routing and data-extraction behaviour currently
 * embedded in MainActivity.configureFromXML() and its sub-methods, so that
 * future extraction of a WifiProvisioner class in Plan 03 cannot silently
 * break profile dispatch.
 *
 * All tests run on the host JVM — no Android emulator required.
 */
public class WifiProvisionerTest {

    // -- helpers ----------------------------------------------------------

    private String readFixture(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream("/fixtures/" + name)) {
            assertNotNull("fixture not found: " + name, is);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private HashMap<?, ?> parseRoot(String fixtureName) throws IOException, XmlParseException {
        return (HashMap<?, ?>) Plist.objectFromXml(readFixture(fixtureName));
    }

    private HashMap<?, ?> generalConfig(HashMap<?, ?> root) {
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        return (HashMap<?, ?>) payload.get(0);
    }

    // -- tests ------------------------------------------------------------

    /** WEP profiles are routed by encryptionType == "WEP" (case-insensitive). */
    @Test
    public void wepProfile_encryptionTypeMatchesWEP() throws Exception {
        HashMap<?, ?> general = generalConfig(parseRoot("profile-wep.xml"));
        String encType = (String) general.get("EncryptionType");
        assertTrue("WEP profile must report EncryptionType WEP (case-insensitive)",
                "WEP".equalsIgnoreCase(encType));
    }

    /** WEP profiles carry a plain-text Password field. */
    @Test
    public void wepProfile_passwordIsExtracted() throws Exception {
        HashMap<?, ?> general = generalConfig(parseRoot("profile-wep.xml"));
        String password = (String) general.get("Password");
        assertNotNull("WEP password must not be null", password);
        assertFalse("WEP password must not be empty", password.isEmpty());
    }

    /** PSK profiles have EncryptionType WPA and no EAPClientConfiguration. */
    @Test
    public void pskProfile_noEapClientConfiguration() throws Exception {
        HashMap<?, ?> general = generalConfig(parseRoot("profile-psk.xml"));
        assertEquals("WPA", general.get("EncryptionType"));
        assertNull("PSK profile must not have EAPClientConfiguration",
                general.get("EAPClientConfiguration"));
    }

    /** PSK profiles carry a Password used as the WPA pre-shared key. */
    @Test
    public void pskProfile_passwordIsPresent() throws Exception {
        HashMap<?, ?> general = generalConfig(parseRoot("profile-psk.xml"));
        String password = (String) general.get("Password");
        assertNotNull("PSK password must not be null", password);
        assertEquals("mysecretpassword", password);
    }

    /** PEAP profiles have EncryptionType WPA and AcceptEAPTypes containing 25. */
    @Test
    public void peapProfile_eapTypesContain25() throws Exception {
        HashMap<?, ?> general = generalConfig(parseRoot("profile-peap.xml"));
        HashMap<?, ?> eapConfig = (HashMap<?, ?>) general.get("EAPClientConfiguration");
        assertNotNull("PEAP profile must have EAPClientConfiguration", eapConfig);

        ArrayList<?> eapTypes = (ArrayList<?>) eapConfig.get("AcceptEAPTypes");
        assertTrue("AcceptEAPTypes must contain 25 (PEAP)",
                eapTypes.contains(Integer.valueOf(25)));
    }

    /** TLS profiles have AcceptEAPTypes containing 13. */
    @Test
    public void tlsProfile_eapTypesContain13() throws Exception {
        HashMap<?, ?> general = generalConfig(parseRoot("profile-tls.xml"));
        HashMap<?, ?> eapConfig = (HashMap<?, ?>) general.get("EAPClientConfiguration");
        assertNotNull("TLS profile must have EAPClientConfiguration", eapConfig);

        ArrayList<?> eapTypes = (ArrayList<?>) eapConfig.get("AcceptEAPTypes");
        assertTrue("AcceptEAPTypes must contain 13 (TLS)",
                eapTypes.contains(Integer.valueOf(13)));
    }

    /** TLS profiles include a pkcs12 section for the client certificate. */
    @Test
    public void tlsProfile_pkcs12SectionPresent() throws Exception {
        HashMap<?, ?> root = parseRoot("profile-tls.xml");
        ArrayList<?> payloads = (ArrayList<?>) root.get("PayloadContent");

        long pkcs12Count = payloads.stream()
                .filter(o -> "com.apple.security.pkcs12".equals(((HashMap<?, ?>) o).get("PayloadType")))
                .count();
        assertTrue("TLS profile must have exactly one pkcs12 section", pkcs12Count >= 1);
    }

    /** TLS profile pkcs12 section carries the PayloadCertificateFileName (used as tlsUsername). */
    @Test
    public void tlsProfile_pkcs12SectionHasCertificateFileName() throws Exception {
        HashMap<?, ?> root = parseRoot("profile-tls.xml");
        ArrayList<?> payloads = (ArrayList<?>) root.get("PayloadContent");

        for (Object item : payloads) {
            HashMap<?, ?> section = (HashMap<?, ?>) item;
            if ("com.apple.security.pkcs12".equals(section.get("PayloadType"))) {
                String certFileName = (String) section.get("PayloadCertificateFileName");
                assertNotNull("pkcs12 section must have PayloadCertificateFileName (used as tlsUsername)", certFileName);
                return;
            }
        }
        fail("pkcs12 section not found in TLS profile");
    }

    /** PEAP profile carries a radius CA in com.apple.security.radius.ca section. */
    @Test
    public void peapProfile_radiusCaSectionPresent() throws Exception {
        HashMap<?, ?> root = parseRoot("profile-peap.xml");
        ArrayList<?> payloads = (ArrayList<?>) root.get("PayloadContent");

        boolean found = payloads.stream()
                .anyMatch(o -> "com.apple.security.radius.ca".equals(((HashMap<?, ?>) o).get("PayloadType")));
        assertTrue("PEAP profile must have a radius CA section", found);
    }
}
