package org.packetfence.agent.plist;

import org.junit.Test;
import xmlwise.Plist;
import xmlwise.XmlParseException;

import java.io.InputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;

import static org.junit.Assert.*;

/**
 * Characterisation tests for plist XML parsing logic.
 *
 * These tests capture the current behaviour of the XML parsing code extracted
 * from MainActivity.parseXML() and MainActivity.configureFromXML(), so that
 * the god-class extraction in Plan 03 cannot silently change parsing semantics.
 *
 * All tests run on the host JVM via xmlwise, which is already in libs/.
 */
public class PlistParserTest {

    // -- helpers ----------------------------------------------------------

    private String readFixture(String name) throws IOException {
        try (InputStream is = getClass().getResourceAsStream("/fixtures/" + name)) {
            assertNotNull("fixture not found: " + name, is);
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    // -- tests ------------------------------------------------------------

    @Test
    public void parsePskProfile_returnsCorrectSsid() throws Exception {
        String xml = readFixture("profile-psk.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        assertEquals("PacketFence-PSK", general.get("SSID_STR"));
    }

    @Test
    public void parsePskProfile_encryptionTypeIsWPA() throws Exception {
        String xml = readFixture("profile-psk.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        assertEquals("WPA", general.get("EncryptionType"));
    }

    @Test
    public void parsePskProfile_passwordPresentWhenNullEapConfig() throws Exception {
        String xml = readFixture("profile-psk.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        // No EAPClientConfiguration means WPA-PSK path
        assertNull(general.get("EAPClientConfiguration"));
        assertEquals("mysecretpassword", general.get("Password"));
    }

    @Test
    public void parseWepProfile_encryptionTypeIsWEP() throws Exception {
        String xml = readFixture("profile-wep.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        assertTrue("EncryptionType must be WEP",
                "WEP".equalsIgnoreCase((String) general.get("EncryptionType")));
        assertEquals("wepkey123", general.get("Password"));
    }

    @Test
    public void parsePeapProfile_eapTypeIs25() throws Exception {
        String xml = readFixture("profile-peap.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        HashMap<?, ?> eapConfig = (HashMap<?, ?>) general.get("EAPClientConfiguration");
        assertNotNull(eapConfig);

        ArrayList<?> eapTypes = (ArrayList<?>) eapConfig.get("AcceptEAPTypes");
        assertTrue("PEAP EAP type 25 must be present",
                eapTypes.contains(Integer.valueOf(25)));
    }

    @Test
    public void parsePeapProfile_usernamePresentInEapConfig() throws Exception {
        String xml = readFixture("profile-peap.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        HashMap<?, ?> eapConfig = (HashMap<?, ?>) general.get("EAPClientConfiguration");
        assertEquals("peap-user", eapConfig.get("UserName"));
    }

    @Test
    public void parseTlsProfile_eapTypeIs13() throws Exception {
        String xml = readFixture("profile-tls.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payload = (ArrayList<?>) root.get("PayloadContent");
        HashMap<?, ?> general = (HashMap<?, ?>) payload.get(0);

        HashMap<?, ?> eapConfig = (HashMap<?, ?>) general.get("EAPClientConfiguration");
        assertNotNull(eapConfig);

        ArrayList<?> eapTypes = (ArrayList<?>) eapConfig.get("AcceptEAPTypes");
        assertTrue("TLS EAP type 13 must be present",
                eapTypes.contains(Integer.valueOf(13)));
    }

    @Test
    public void parseTlsProfile_pkcs12PayloadTypeDetected() throws Exception {
        String xml = readFixture("profile-tls.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payloads = (ArrayList<?>) root.get("PayloadContent");

        boolean found = false;
        for (Object item : payloads) {
            HashMap<?, ?> section = (HashMap<?, ?>) item;
            if ("com.apple.security.pkcs12".equals(section.get("PayloadType"))) {
                found = true;
                break;
            }
        }
        assertTrue("PKCS12 payload section must be present in TLS profile", found);
    }

    @Test
    public void parseTlsProfile_rootCaPayloadTypeDetected() throws Exception {
        String xml = readFixture("profile-tls.xml");
        HashMap<?, ?> root = (HashMap<?, ?>) Plist.objectFromXml(xml);
        ArrayList<?> payloads = (ArrayList<?>) root.get("PayloadContent");

        boolean found = false;
        for (Object item : payloads) {
            HashMap<?, ?> section = (HashMap<?, ?>) item;
            if ("com.apple.security.root".equals(section.get("PayloadType"))) {
                found = true;
                break;
            }
        }
        assertTrue("Root CA payload section must be present in TLS profile", found);
    }

    @Test(expected = XmlParseException.class)
    public void parseMalformedXml_throwsXmlParseException() throws Exception {
        Plist.objectFromXml("this is not xml at all <<<>>>");
    }

    @Test(expected = XmlParseException.class)
    public void parseEmptyString_throwsXmlParseException() throws Exception {
        Plist.objectFromXml("");
    }
}
