package org.packetfence.agent;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.*;
import android.graphics.Color;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.SupplicantState;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSuggestion;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.security.KeyChain;
import android.text.InputType;
import android.text.TextUtils;
import android.util.Base64;
import android.view.*;
import android.widget.*;
import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;
import xmlwise.Plist;
import xmlwise.XmlParseException;

import javax.security.cert.X509Certificate;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class MainActivity extends Activity {

    private boolean isDebugMode = false;
    private boolean isDebugSteps = false;
    private int debugCount = 0;
    private static final int FLOW_CA = 20;
    private static final int FLOW_BIB = 25;
    private static final int api_version = Build.VERSION.SDK_INT;
    public static String discoveryUrl = "http://wireless-profiles.packetfence.org/packetfence-android-agent-test";
    // Just used for testing purposes when you want to force a URL to be used
    // A production build should always have this value set to null
    public static String overrideProfileUrl = null;
    public static int EAPTYPE_TLS = 13;
    public static int EAPTYPE_LEAP = 17;
    public static int EAPTYPE_TTLS = 21;
    public static int EAPTYPE_PEAP = 25;
    public static int EAPTYPE_EAP_FAST = 43;
    public static boolean done_configuring = false;
    public String profileDomainName = null;
    public String profileProto = "https";
    public String profilePath = "/profile.xml";
    private HashMap profile;
    private String userP12Name;
    private byte[] userP12;
    private String password = "";
    private String caCrtString;
    private String serverCN = "";
    private String ssid;
    private String tlsUsername;
    private Context context;
    private PrivateKey userPrivateKey;
    private java.security.cert.X509Certificate userCertificate;
    private java.security.cert.Certificate[] userCertificates;
    private java.security.cert.X509Certificate[] caCertificates;
    private List<java.security.cert.X509Certificate> caCertificatesTmp;
    private java.security.cert.X509Certificate caCertificate;
    private BroadcastReceiver broadcastReceiver;
    private String debugOutputSteps = "";
    private String debugConfigOutput = "";

    /*
     * Set DEBUG
     */
    public void changeDebugStatus(View view) {
        if (debugCount<2){
            debugCount+=1;
        } else {
            showInBox("Change debug status");
            if (isDebugMode || isDebugSteps){
                isDebugSteps = false;
                isDebugMode = false;
            } else {
                isDebugSteps = true;
                isDebugMode = true;
            }
            updateDebugTextVisible(isDebugSteps);
            debugCount=0;
        }
    }

    public void updateDebugTextVisible(boolean bool) {
        TextView b = findViewById(R.id.debug_text);
        if (bool) {
            b.setVisibility(View.VISIBLE);
        } else {
            b.setVisibility(View.INVISIBLE);
        }
    }

    /*
     * OVERRIDES
     */
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    /*
     * QUIT
     */
    public void addTodebugConfigOutput(String text){
        showInBoxIfDebug(text);
        debugConfigOutput = debugConfigOutput + "\n" + text;
    }

    public void showDebugOrExit(){
        Map<String, String> connectionInfo = getCurrentConnectionInfo(MainActivity.this);
        for (Map.Entry<String, String> entry : connectionInfo.entrySet()) {
            addTodebugConfigOutput(entry.getKey()+" => "+entry.getValue());
        }

        if (isDebugMode || isDebugSteps) {
            TextView showText = new TextView(this);
            String st = debugConfigOutput;
            if (isDebugSteps){
                st = st+"\n\n"+debugOutputSteps;
            }
            showText.setText(st);
            showText.setTextIsSelectable(true);

            final String mess = "Exit";

            AlertDialog.Builder alert00 = new AlertDialog.Builder(
                    MainActivity.this);
            alert00.setCancelable(false);
            alert00.setTitle("Debug Output");
            alert00.setView(showText);
            alert00.setPositiveButton(mess,
                    new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            MainActivity.this.done_configuring = true;
                        }
                    });
            alert00.show();
        } else {
            MainActivity.this.done_configuring = true;
        }
    }

    public void quit(View view) {
        //System.exit(0);
        stopApplicationAfterSeconds(2);
    }

    public void stopApplicationAfterSeconds(int sec) {
        int inum = sec * 1000;
        Long lnum = Long.valueOf(inum);
        Handler handler = new Handler();
        handler.postDelayed(new Runnable() {
            public void run() {
            }
        }, lnum);
        MainActivity.this.finish();
        MainActivity.this.moveTaskToBack(true);
    }

    /*
     * SHOW INFORMATION
     */
    public void showInBoxIfDebug(String text) {
        if (isDebugMode) {
            showInBox(text);
            showInConsole(text);
        }
    }

    public void showInConsole(String text) {
        if (isDebugMode) {
            System.out.println(text);
        }
    }

    public void showInBox(String text) {
        MainActivity.this.debugOutputSteps = MainActivity.this.debugOutputSteps+"\n"+text;
        final Activity view = this;
        Toast.makeText(view, text, Toast.LENGTH_LONG)
                .show();
    }

    public void enableConfigButton(boolean bool) {
        Button b = findViewById(R.id.button1);
        b.setEnabled(bool);
    }

    public void showNetworkError(int iman) {
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL) {
            addTodebugConfigOutput("The packetfence agent suggestions had an internal error.");
            addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED) {
            addTodebugConfigOutput("The packetfence agent suggestions are disallowed.");
            addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE) {
            addTodebugConfigOutput("The packetfence agent has suggested a duplicate network.");
            addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP) {
            addTodebugConfigOutput("The packetfence agent exceeds the maximum of network suggestions per application.");
            addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID) {
            addTodebugConfigOutput("The " + this.ssid + " is not available in suggestions networks.");
            addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
        }
        // Added in API 30
        if (MainActivity.this.api_version >= 30) {
            if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED){
                addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED");
            }
            if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID){
                addTodebugConfigOutput("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID");
            }
         }
    }

    /*
     * DIALOG BOXES
     */
    // Dialog after API 29
    // Source: https://stackoverflow.com/a/49272722
    public void showDialogAfterAPI29() {
        int llPadding = 30;
        LinearLayout ll = new LinearLayout(this);
        ll.setOrientation(LinearLayout.HORIZONTAL);
        ll.setPadding(llPadding, llPadding, llPadding, llPadding);
        ll.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams llParam = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT);
        llParam.gravity = Gravity.CENTER;
        ll.setLayoutParams(llParam);

        ProgressBar progressBar = new ProgressBar(this);
        progressBar.setIndeterminate(true);
        progressBar.setPadding(0, 0, llPadding, 0);
        progressBar.setLayoutParams(llParam);

        llParam = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        llParam.gravity = Gravity.CENTER;
        TextView tvText = new TextView(this);
        tvText.setText("Please wait\n" +
                "Now Configuring...");
        tvText.setTextColor(Color.parseColor("#ffffff"));
        tvText.setTextSize(18);
        tvText.setLayoutParams(llParam);

        ll.addView(progressBar);
        ll.addView(tvText);

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setCancelable(false);
        builder.setView(ll);

        final AlertDialog dialog = builder.create();
        dialog.show();
        Window window = dialog.getWindow();
        if (window != null) {
            WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
            layoutParams.copyFrom(dialog.getWindow().getAttributes());
            layoutParams.width = LinearLayout.LayoutParams.WRAP_CONTENT;
            layoutParams.height = LinearLayout.LayoutParams.WRAP_CONTENT;
            dialog.getWindow().setAttributes(layoutParams);
        }
        // Show it for at least 5 seconds...
        new Thread(new Runnable() {
            @Override
            public void run() {
                // TODO Auto-generated method stub
                Looper.prepare();
                try {
                    int t = 0;
                    while (!MainActivity.this.done_configuring || t < 5000) {
                        Thread.sleep(100);
                        t += 100;
                    }
                } catch (Exception e) {
                }
                dialog.dismiss();
            }
        }).start();
    }

    // Dialog before API29
    public void showDialogBeforeAPI29() {
        final ProgressDialog myPd_ring = ProgressDialog.show(MainActivity.this,
                "Please wait", "Configuring...", true);
        myPd_ring.setCancelable(false);

        // Show it for at least 5 seconds...
        new Thread(new Runnable() {
            @Override
            public void run() {
                // TODO Auto-generated method stub
                Looper.prepare();
                try {
                    int t = 0;
                    while (!MainActivity.this.done_configuring || t < 5000) {
                        Thread.sleep(100);
                        t += 100;
                    }
                } catch (Exception e) {
                }
                myPd_ring.dismiss();
            }
        }).start();
    }

    /*
     * FROM CONFIGURATION BUTTON
     */
    public void configure(View view) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException {
        MainActivity.this.context = view.getContext();

        //Reset Values
        debugOutputSteps = "\n\n####\nSteps\n####\n";
        debugConfigOutput = "API version: "+Build.VERSION.SDK_INT;
        if (MainActivity.this.api_version >= 29) {
            showDialogAfterAPI29();
        } else {
            showDialogBeforeAPI29();
        }
        enableConfigButton(false);
        fetchPortalDomainName();
    }

    /*
     * TEST SECURE CONNEXION TO EXTRACT XML
     */
    public void fetchPortalDomainName() {
        addTodebugConfigOutput("=== fetchPortalDomainName ===");
        WifiManager wifiManager = (WifiManager) MainActivity.this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (!wifiManager.isWifiEnabled()) {
            showInBox("Please enable wifi first");
            showDebugOrExit();
        }

        if (MainActivity.this.overrideProfileUrl != null) {
            fetchXML();
            return;
        }

        org.packetfence.agent.DiscoveryStringRequest stringRequest =
                new org.packetfence.agent.DiscoveryStringRequest(Request.Method.GET, MainActivity.this.discoveryUrl,
                new Response.Listener<org.packetfence.agent.DiscoveryStringRequest.ResponseM>() {

                    @Override
                    public void onResponse(org.packetfence.agent.DiscoveryStringRequest.ResponseM response) {
                        addTodebugConfigOutput("Profile domain name probe was successful");
                        String location = null;
                        if(response.headers.get("Location") != null) {
                            location = response.headers.get("Location");
                        }
                        else if (response.headers.get("location") != null) {
                            location = response.headers.get("location");
                        }
                        try {
                            addTodebugConfigOutput("Found location header value: " + location);
                            URL url = new URL(location);
                            MainActivity.this.profileDomainName = url.getHost();
                            addTodebugConfigOutput("Found domain name: " + MainActivity.this.profileDomainName);
                            fetchXML();
                        } catch (MalformedURLException e) {
                            addTodebugConfigOutput("Unable to detect domain name from domain probe");
                            showDebugOrExit();
                        }
                    }
        }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                if (error.networkResponse == null) {
                    addTodebugConfigOutput("Network error while finding profile domain name: " + error.getLocalizedMessage());
                } else {
                    addTodebugConfigOutput("Error fetching profile");
                }
                showDebugOrExit();
            }
        });
        RequestQueue queue = Volley.newRequestQueue(MainActivity.this);
        queue.add(stringRequest);
    }

    /*
     * XML PART
     */
    public void fetchXML() {
        addTodebugConfigOutput("=== fetchXML ===");
        String profileUrl;
        if (MainActivity.this.overrideProfileUrl != null) {
            profileUrl = MainActivity.this.overrideProfileUrl;
        } else {
            profileUrl = MainActivity.this.profileProto + "://" + MainActivity.this.profileDomainName + MainActivity.this.profilePath;
        }

        StringRequest stringRequest = new StringRequest(Request.Method.GET, profileUrl,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        addTodebugConfigOutput("Downloaded profile successfully");
                        fetchXMLCallback(response);
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                if (error.networkResponse == null) {
                    addTodebugConfigOutput("Network error: " + error.getLocalizedMessage());
                } else if (error.networkResponse.statusCode == 404) {
                    addTodebugConfigOutput("Profile not found on server.");
                } else {
                    addTodebugConfigOutput("Error fetching profile ");
                }
                showDebugOrExit();
            }
        });
        RequestQueue queue = Volley.newRequestQueue(MainActivity.this);
        queue.add(stringRequest);
    }

    public void fetchXMLCallback(String content) {
        addTodebugConfigOutput("=== fetchXMLCallback ===");
        if (content != null) {
            addTodebugConfigOutput(content);
            Object[] categoryObj = parseXML(content);
            configureFromXML(categoryObj);
        } else {
            addTodebugConfigOutput("Unable to fetch configuration profile.");
            showDebugOrExit();
        }
    }

    public Object[] parseXML(String xml) {
        addTodebugConfigOutput("=== parseXML ===");
        //public void parseXML(String xml) {
        Object[] categoryObj = new Object[0];
        try {
            HashMap<?, ?> hashMap = (HashMap<?, ?>) Plist.objectFromXml(xml);

            ArrayList<?> category = (ArrayList<?>) hashMap
                    .get("PayloadContent");
            MainActivity.this.profile = hashMap;

            categoryObj = category.toArray();
        } catch (XmlParseException e) {
            addTodebugConfigOutput("Error PXML1:" + e.getMessage());
        }
        return categoryObj;
    }

    /*
     * WIRELESS CONFIGURATION
     */
    public void configureFromXML(Object[] categoryObj) {
        addTodebugConfigOutput("=== configureFromXML ===");
        // First one contains the general configuration
        HashMap<?, ?> generalConfig = (HashMap<?, ?>) categoryObj[0];
        MainActivity.this.ssid = (String) generalConfig.get("SSID_STR");
        addTodebugConfigOutput("SSID : " + MainActivity.this.ssid);

        // We first clear any previous configuration for the SSID
        clearConfiguration();

        String encryptionType = (String) generalConfig
                .get("EncryptionType");

        addTodebugConfigOutput("encryption type : " + encryptionType);

        // Values are: WPA (PEAP, PSK), WEP
        // We first handle WEP
        if (encryptionType.equalsIgnoreCase("WEP")) {
            MainActivity.this.password = (String) generalConfig.get("Password");
            configureWirelessConnectionWEP();
        }
        // Now handle WPA (PEAP and PSK)
        else if (encryptionType.equalsIgnoreCase("WPA")) {
            configureWirelessConnectionWPAPEAPAndEAPTLS(categoryObj, generalConfig);
        }
    }

    /*
     * Wireless Configurations WEP
     */
    public void configureWirelessConnectionWEP() {
        addTodebugConfigOutput("=== configureWirelessConnectionWEP ===");
        // Check the api version
        if (MainActivity.this.api_version >= 29) {
            configureWEPAfterAPI29();
        } else if (MainActivity.this.api_version < 29) {
            configureWEPBeforeAPI29();
        }
    }

    // TODO: Change it for api 29 currently equal to before 29
    public void configureWEPAfterAPI29() {
        addTodebugConfigOutput("=== configureWEPAfterAPI29 ===");
        addTodebugConfigOutput("It is no more supported by the Android API");
        showDebugOrExit();
    }

    public void configureWEPBeforeAPI29() {
        addTodebugConfigOutput("=== configureWEPBeforeAPI29 ===");
        WifiConfiguration wc = new WifiConfiguration();

        wc.SSID = "\"" + MainActivity.this.ssid + "\"";
        wc.hiddenSSID = false;
        wc.status = WifiConfiguration.Status.ENABLED;
        wc.priority = 40;
        wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.NONE);
        wc.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        wc.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
        wc.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
        wc.allowedAuthAlgorithms
                .set(WifiConfiguration.AuthAlgorithm.SHARED);
        wc.allowedPairwiseCiphers
                .set(WifiConfiguration.PairwiseCipher.CCMP);
        wc.allowedPairwiseCiphers
                .set(WifiConfiguration.PairwiseCipher.TKIP);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        wc.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

        wc.wepKeys[0] = "\"" + MainActivity.this.password + "\"";//
        wc.wepTxKeyIndex = 0;

        enableWifiConfiguration(wc);
    }

    /*
     * Wireless Configurations WPA-PEAP And EAP-TLS
     */
    public void configureWirelessConnectionWPAPEAPAndEAPTLS(Object[] categoryObj, HashMap<?, ?> generalConfig) {
        addTodebugConfigOutput("=== configureWirelessConnectionWPAPEAPAndEAPTLS ===");
        HashMap<?, ?> eapClientConfigurationHashMap = (HashMap<?, ?>) generalConfig
                .get("EAPClientConfiguration");

        // Handling WPA-PEAP and EAP-TLS
        if (eapClientConfigurationHashMap != null) {
            addTodebugConfigOutput("Detected WPA EAP configuration");
            ArrayList<?> eapTypes = (ArrayList<?>) eapClientConfigurationHashMap.get("AcceptEAPTypes");
            MainActivity.this.caCertificatesTmp = new ArrayList<java.security.cert.X509Certificate>();

            if (eapTypes.contains(Integer.valueOf(EAPTYPE_TLS))) {
                addTodebugConfigOutput("Detected WPA EAP-TLS configuration");
                // We skip the first section
                for (int i = 1; i < categoryObj.length; i++) {
                    HashMap<?, ?> config = (HashMap<?, ?>) categoryObj[i];
                    if (config.containsKey("PayloadType")) {
                        String payloadType = (String) (config.get("PayloadType"));
                        if (payloadType!=null && payloadType.equals("com.apple.security.root")) {
                            addTodebugConfigOutput("Found root certificate");

                            MainActivity.this.caCrtString = "-----BEGIN CERTIFICATE-----\n";
                            MainActivity.this.caCrtString += (String) config.get("PayloadContent");
                            MainActivity.this.caCrtString += "\n";
                            MainActivity.this.caCrtString += "-----END CERTIFICATE-----";
                            java.security.cert.X509Certificate zayme = createX509CertFromString(MainActivity.this.caCrtString);
                            MainActivity.this.caCertificate=zayme;
                            MainActivity.this.caCertificatesTmp.add(zayme);
                        }
                        if (payloadType!=null && payloadType.equals("com.apple.security.pkcs12")) {
                            addTodebugConfigOutput("Found the EAP-TLS p12 certificate");
                            String p12BytesB64 = (String) config.get("PayloadContent");

                            byte[] p12Bytes = Base64.decode(p12BytesB64.getBytes(), Base64.DEFAULT);

                            MainActivity.this.userP12 = p12Bytes;
                            MainActivity.this.userP12Name = (String) config.get("PayloadDisplayName");
                            MainActivity.this.tlsUsername = (String) config.get("PayloadCertificateFileName");
                            addTodebugConfigOutput("userP12Name >>"+MainActivity.this.userP12Name);
                            addTodebugConfigOutput("tlsUsername >>"+MainActivity.this.tlsUsername);
                        }
                        if (payloadType!=null && payloadType.equals("com.apple.security.pkcs1")) {
                            addTodebugConfigOutput("Found the EAP-TLS root certificate");
                            MainActivity.this.serverCN = (String) config.get("PayloadCertificateFileName");
                            addTodebugConfigOutput("serverCN >>"+MainActivity.this.serverCN);
                        }
                        if (payloadType!=null && payloadType.equals("com.apple.security.other_ca")) {
                            addTodebugConfigOutput("Found another radius CA certificates");
                            String zayme_content_from_other_ca = (String) config.get("PayloadContent");
                            java.security.cert.X509Certificate zayme = createX509CertFromString(zayme_content_from_other_ca);
                            MainActivity.this.caCertificatesTmp.add(zayme);
                        }
                    }
                }
                if (MainActivity.this.serverCN.equals("") && MainActivity.this.api_version >= 34){
                    misconfiguration();
                } else {
                    if (!MainActivity.this.caCertificatesTmp.isEmpty()) {
                        MainActivity.this.caCertificates = MainActivity.this.caCertificatesTmp.toArray(new java.security.cert.X509Certificate[0]);
                    }
                    configureWirelessConnectionWPA2TLS();
                }

            } else if (eapTypes.contains(Integer.valueOf(EAPTYPE_PEAP))) {
                addTodebugConfigOutput("Detected WPA EAP-PEAP configuration");
                MainActivity.this.tlsUsername = (String) eapClientConfigurationHashMap.get("UserName");
                addTodebugConfigOutput("tlsUsername >>"+MainActivity.this.tlsUsername);
                for (int i = 1; i < categoryObj.length; i++) {
                    HashMap<?, ?> config = (HashMap<?, ?>) categoryObj[i];
                    if (config.containsKey("PayloadType")) {
                        String payloadType = (String) (config.get("PayloadType"));
                        if (payloadType!=null && payloadType.equals("com.apple.security.radius.ca")) {
                            addTodebugConfigOutput("Found radius root certificate");
                            MainActivity.this.caCrtString = "-----BEGIN CERTIFICATE-----\n";
                            MainActivity.this.caCrtString += (String) config.get("PayloadContent");
                            MainActivity.this.caCrtString += "\n";
                            MainActivity.this.caCrtString += "-----END CERTIFICATE-----";
                            java.security.cert.X509Certificate zayme = createX509CertFromString(MainActivity.this.caCrtString);
                            MainActivity.this.caCertificate=zayme;
                            MainActivity.this.caCertificatesTmp.add(zayme);
                        }
                        if (payloadType!=null && payloadType.equals("com.apple.security.root")) {
                            addTodebugConfigOutput("Found the EAP-PEAP root certificate");
                            MainActivity.this.serverCN = (String) config.get("PayloadCertificateFileName");
                            addTodebugConfigOutput("serverCN >>"+MainActivity.this.serverCN);
                        }
                        if (payloadType!=null && payloadType.equals("com.apple.security.other_ca")) {
                            addTodebugConfigOutput("Found another radius CA certificates");
                            String zayme_content_from_other_ca = (String) config.get("PayloadContent");
                            java.security.cert.X509Certificate zayme = createX509CertFromString(zayme_content_from_other_ca);
                            MainActivity.this.caCertificatesTmp.add(zayme);
                        }
                    }
                }
                if (MainActivity.this.caCrtString.isEmpty() && MainActivity.this.api_version >= 34){
                    misconfiguration();
                } else {
                    if (MainActivity.this.caCertificatesTmp.size() > 1) {
                        MainActivity.this.caCertificates = MainActivity.this.caCertificatesTmp.toArray(new java.security.cert.X509Certificate[0]);
                    }
                    configureWirelessConnectionWPA2PEAP();
                }
            }
        }
        // Handling WPA-PSK
        else {
            addTodebugConfigOutput("WPA WPA-PSK configuration");
            MainActivity.this.password = (String) generalConfig.get("Password");
            configureWirelessConnectionWPAPSK();
        }
    }

    /* WPA2TLS */
    public void configureWirelessConnectionWPA2TLS() {
        addTodebugConfigOutput("=== configureWirelessConnectionWPA2TLS ===");
        final EditText input = new EditText(MainActivity.this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        AlertDialog.Builder alert02 = new AlertDialog.Builder(MainActivity.this);
        alert02.setCancelable(false);
        alert02.setTitle("Certificate password");
        alert02.setMessage("Enter the password to unlock the certificate for user: " + MainActivity.this.tlsUsername);
        alert02.setView(input);
        alert02.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                MainActivity.this.password = input.getText().toString();
                computeUserCertAndKey();
            }
        });
        alert02.show();
    }

    public void computeUserCertAndKey() {
        addTodebugConfigOutput("=== computeUserCertAndKey ===");
        KeyStore p12;
        boolean certIsGood = false;
        try {
            p12 = KeyStore.getInstance("pkcs12");
            p12.load(new ByteArrayInputStream(MainActivity.this.userP12),
                    MainActivity.this.password.toCharArray());
            Enumeration ee = p12.aliases();
            addTodebugConfigOutput("My NUM OF ALIAS IS "+Integer.toString(p12.size()));
            while (ee.hasMoreElements()) {
                String alias = (String) ee.nextElement();
                MainActivity.this.userCertificate = (java.security.cert.X509Certificate) p12.getCertificate(alias);
                MainActivity.this.userCertificates = p12.getCertificateChain(alias);
                MainActivity.this.userPrivateKey = (PrivateKey) p12.getKey(alias,
                        MainActivity.this.password.toCharArray());
            }
            certIsGood = true;
        } catch (KeyStoreException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CK1:" + e.getMessage());
        } catch (IOException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CK2:" + e.getMessage());
            enableConfigButton(true);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CK3:" + e.getMessage());
        } catch (CertificateException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CK4:" + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            addTodebugConfigOutput("Error CK5:" + e.getMessage());
            e.printStackTrace();
        }

        if (certIsGood) {
            addTodebugConfigOutput("CertificateChain content is");
            for ( java.security.cert.Certificate cert : MainActivity.this.userCertificates ){
                addTodebugConfigOutput(cert.toString());
            }
            if (MainActivity.this.api_version >= 29) {
                configureWPA2TLSAfterAPI29();
            } else if (MainActivity.this.api_version > 19 && MainActivity.this.api_version < 29) {
                configureWPA2TLSAPI20();
            } else {
                configureWPA2TLSBeforeAPI29();
            }
        } else {
            showInBox("The certificate is not extracted. The configuration will stop.");
            showDebugOrExit();
        }
    }

    public void configureWPA2TLSAfterAPI29() {
        addTodebugConfigOutput("=== configureWPA2TLSAfterAPI29 ===");
        WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();
        mEnterpriseConfig.setIdentity(MainActivity.this.tlsUsername);
        mEnterpriseConfig.setPassword("test");

        if (MainActivity.this.caCertificates.length > 1) {
            mEnterpriseConfig.setCaCertificates(MainActivity.this.caCertificates);
        } else {
            mEnterpriseConfig.setCaCertificate(MainActivity.this.caCertificate);
        }

        mEnterpriseConfig.setClientKeyEntry(MainActivity.this.userPrivateKey,
                MainActivity.this.userCertificate);

        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.NONE);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.TLS);
        mEnterpriseConfig.setDomainSuffixMatch(MainActivity.this.serverCN);

        final WifiNetworkSuggestion suggestion = new WifiNetworkSuggestion.Builder()
                .setSsid(MainActivity.this.ssid)
                .setWpa2EnterpriseConfig(mEnterpriseConfig)
                .setIsAppInteractionRequired(false)
                .setPriority(100)
                .build();

        final List<WifiNetworkSuggestion> suggestionsList = new ArrayList<WifiNetworkSuggestion>();
        suggestionsList.add(suggestion);
        alertDialogAfterAPI29(suggestionsList);
    }

    // Alert Dialog for server misconfiguration
    public void misconfiguration() {
        addTodebugConfigOutput("=== misconfiguration ===");
        StringBuilder sb = new StringBuilder();
        sb.append("Your android version is not compatible with the current server settings\n");
        sb.append("\n");
        sb.append("Please contact your system administrator.\n");

        final String mess = "Ok";

        AlertDialog.Builder alertMiss = new AlertDialog.Builder(MainActivity.this);
        alertMiss.setCancelable(false);
        alertMiss.setTitle("Server Misconfiguration");
        alertMiss.setMessage(sb);
        alertMiss.setPositiveButton(mess,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        showDebugOrExit();
                    }
                });
        alertMiss.show();
    }

    // Alert Dialog for API 29 Part 1
    public void alertDialogAfterAPI29(final List<WifiNetworkSuggestion> suggestionsList) {
        StringBuilder sb = new StringBuilder();
        sb.append("\nStep 1:\n");
        sb.append("The WiFi settings will open\n");
        sb.append("\nStep 2:\n");
        sb.append("Forget the current WiFi network you're connected on\n");
        sb.append("\nStep 3:\n");
        sb.append("Allow PacketFence Agent to modify the WiFi configuration.\n" +
                "NOTE: On Android 10, the request is silent and will be in your notifications.\n");
        sb.append("\nStep 4:\n");
        sb.append("Ensure that your device is not connected to any WiFi network.\n");
        sb.append("\nStep 5:\n");
        sb.append("Wait until the new ssid (" + MainActivity.this.ssid + ") is connected with the comment 'Connected via PacketFence Agent'\n");

        final String mess = "Next";

        AlertDialog.Builder alert03 = new AlertDialog.Builder(
                MainActivity.this);
        alert03.setCancelable(false);
        alert03.setTitle("Next steps:");
        alert03.setMessage(sb);
        alert03.setPositiveButton(mess,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        howToDialogAfterAPI29(suggestionsList);
                    }
                });
        if (isDebugMode || isDebugSteps) {
            alert03.setNegativeButton("Show Debug",
                    new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            showDebugConfigOutput(suggestionsList);
                        }
                    });
        }
        alert03.show();
    }

    public void showDebugConfigOutput(final List<WifiNetworkSuggestion> suggestionsList){
        TextView showText = new TextView(this);
        String st = debugConfigOutput;
        if (isDebugSteps){
            st = st+"\n"+debugOutputSteps;
        }
        showText.setText(st);
        showText.setTextIsSelectable(true);

        final String mess = "Return";

        AlertDialog.Builder alert04 = new AlertDialog.Builder(
                MainActivity.this);
        alert04.setCancelable(false);
        alert04.setTitle("Debug Output");
        alert04.setView(showText);
        alert04.setPositiveButton(mess,
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        alertDialogAfterAPI29(suggestionsList);
                    }
        });
        alert04.show();
    }


    // Alert Dialog for API 29 Part 2
    public void howToDialogAfterAPI29(final List<WifiNetworkSuggestion> suggestionsList) {
        StringBuilder sb = new StringBuilder();
        sb.append("If you want to forget the WiFi network:");
        sb.append("\nTo forget " + MainActivity.this.ssid + ", you will need to remove the application \"PacketFence Agent\".\n");
        sb.append("\nNEVER use the 'Forget' or 'Disconnect' button on the \"" + MainActivity.this.ssid + "\" SSID.\n" +
                "If you do, you will not be able to use it for the next 24 hours.\n");
        sb.append("\nChanging " + MainActivity.this.ssid + " settings:\n" +
                "Unfortunately, this will not be possible. It is managed by the application PacketFence Agent.\n" +
                "This is the new android way to set WiFi access. It prevents applications to change your network settings without your consent.\n");

        AlertDialog.Builder alert05 = new AlertDialog.Builder(
                MainActivity.this);
        alert05.setCancelable(false);
        alert05.setTitle("IMPORTANT NOTES:");
        alert05.setMessage(sb);
        alert05.setNegativeButton("OK, I've got it. Let's GO!",
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        showInBox("You will now be redirected to the wifi configuration");
                        enableWifiConfiguration(suggestionsList);
                    }
                });
        alert05.setPositiveButton("Previous",
                new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        alertDialogAfterAPI29(suggestionsList);
                    }
                });
        alert05.show();
    }

    // Configure WPA2TLS Before API 29
    public void configureWPA2TLSBeforeAPI29() {
        addTodebugConfigOutput("=== configureWPA2TLSBeforeAPI29 ===");
        WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();

        mEnterpriseConfig.setIdentity(MainActivity.this.tlsUsername);
        mEnterpriseConfig.setPassword("test");
        mEnterpriseConfig.setCaCertificate(MainActivity.this.caCertificate);
        mEnterpriseConfig.setClientKeyEntry(MainActivity.this.userPrivateKey, MainActivity.this.userCertificate);
        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.NONE);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.TLS);

        WifiConfiguration wc = new WifiConfiguration();

        /*Key Mgmnt*/
        wc.allowedKeyManagement.clear();
        wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
        wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        /*Group Ciphers*/
        wc.allowedGroupCiphers.clear();
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

        /*Pairwise ciphers*/
        wc.allowedPairwiseCiphers.clear();
        wc.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        wc.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

        /*Protocols*/
        wc.allowedProtocols.clear();
        wc.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        wc.allowedProtocols.set(WifiConfiguration.Protocol.WPA);


        wc.networkId = -1;
        wc.SSID = '"' + MainActivity.this.ssid + '"';
        wc.enterpriseConfig = mEnterpriseConfig;

        enableWifiConfiguration(wc);
    }

    public void configureWPA2TLSAPI20() {
        addTodebugConfigOutput("=== configureWPA2TLSAPI20 ===");
        String displayName = MainActivity.this.userP12Name;
        Intent installIntent = KeyChain.createInstallIntent();
        installIntent.putExtra(KeyChain.EXTRA_NAME, displayName);
        try {
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, MainActivity.this.caCertificate.getEncoded());
        } catch (Exception e) {
            addTodebugConfigOutput("error while parsing certificate:" + e.getMessage());
            showDebugOrExit();
        }
        startActivityForResult(installIntent, MainActivity.this.FLOW_CA);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        addTodebugConfigOutput("=== onActivityResult ===");
        addTodebugConfigOutput("Activity Results");
        if (requestCode == MainActivity.this.FLOW_CA) {
            addTodebugConfigOutput("FLOW_CA");
            configureWPA2TLSBeforeAPI29();
        } else if (requestCode == MainActivity.this.FLOW_BIB) {
            addTodebugConfigOutput("FLOW_BIB");
            showDebugOrExit();
        } else {
            addTodebugConfigOutput("Request code is: "+requestCode);
            showDebugOrExit();
        }
    }

    /* WPA2PEAP */
    public void configureWirelessConnectionWPA2PEAP() {
        addTodebugConfigOutput("=== configureWirelessConnectionWPA2PEAP ===");
        final EditText input = new EditText(MainActivity.this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        AlertDialog.Builder alert07 = new AlertDialog.Builder(MainActivity.this);
        alert07.setCancelable(false);
        alert07.setTitle("User password");
        if (MainActivity.this.tlsUsername != null || MainActivity.this.tlsUsername.trim().length() > 0) {
            alert07.setMessage("Enter password for " + MainActivity.this.tlsUsername);
        }
        alert07.setView(input);
        alert07.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                MainActivity.this.password = input.getText().toString();
                if (MainActivity.this.api_version >= 29) {
                    configureWPA2PEAPAfterAPI29();
                } else {
                    configureWPA2PEAPBeforeAPI29();
                }
            }
        });
        alert07.show();
    }

    public void configureWPA2PEAPAfterAPI29() {
        addTodebugConfigOutput("=== configureWPA2PEAPAfterAPI29 ===");
        WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();
        mEnterpriseConfig.setIdentity(MainActivity.this.tlsUsername);
        mEnterpriseConfig.setAnonymousIdentity(MainActivity.this.tlsUsername);
        mEnterpriseConfig.setPassword(MainActivity.this.password);
        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.MSCHAPV2);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.PEAP);
        mEnterpriseConfig.setDomainSuffixMatch(MainActivity.this.serverCN);
        // Multiple Certificates
        if (MainActivity.this.caCertificates.length > 1) {
            mEnterpriseConfig.setCaCertificates(MainActivity.this.caCertificates);
        } else {
            mEnterpriseConfig.setCaCertificate(MainActivity.this.caCertificate);
        }

        WifiNetworkSuggestion suggestionTmp= new WifiNetworkSuggestion.Builder()
                .setSsid(MainActivity.this.ssid)
                .setWpa2EnterpriseConfig(mEnterpriseConfig)
                .setIsAppInteractionRequired(false)
                .setPriority(100)
                .build();

        if (MainActivity.this.api_version >= 31) {
            suggestionTmp = new WifiNetworkSuggestion.Builder()
                    .setSsid(MainActivity.this.ssid)
                    .setWpa2EnterpriseConfig(mEnterpriseConfig)
                    .setIsAppInteractionRequired(false)
                    .setPriority(100)
                    .setMacRandomizationSetting(WifiNetworkSuggestion.RANDOMIZATION_PERSISTENT)
                    .build();
        }

        final WifiNetworkSuggestion suggestion = suggestionTmp;
        final List<WifiNetworkSuggestion> suggestionsList = new ArrayList<WifiNetworkSuggestion>();
        suggestionsList.add(suggestion);
        alertDialogAfterAPI29(suggestionsList);
    }

    public void configureWPA2PEAPBeforeAPI29() {
        addTodebugConfigOutput("=== configureWPA2PEAPBeforeAPI29 ===");
        addTodebugConfigOutput("Configuring " + MainActivity.this.ssid +
                " with username " + MainActivity.this.tlsUsername +
                " and password " + MainActivity.this.password);

        WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();
        mEnterpriseConfig.setIdentity(MainActivity.this.tlsUsername);
        mEnterpriseConfig.setAnonymousIdentity(MainActivity.this.tlsUsername);
        mEnterpriseConfig.setPassword(MainActivity.this.password);

        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.MSCHAPV2);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.PEAP);

        WifiConfiguration wc = new WifiConfiguration();
        /*Key Mgmnt*/
        wc.allowedKeyManagement.clear();
        wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
        wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        /*Group Ciphers*/
        wc.allowedGroupCiphers.clear();
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        wc.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

        /*Pairwise ciphers*/
        wc.allowedPairwiseCiphers.clear();
        wc.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        wc.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

        /*Protocols*/
        wc.allowedProtocols.clear();
        wc.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        wc.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

        wc.networkId = -1;
        wc.SSID = '"' + MainActivity.this.ssid + '"';
        wc.enterpriseConfig = mEnterpriseConfig;

        enableWifiConfiguration(wc);
    }

    /* WPAPSK */
    public void configureWirelessConnectionWPAPSK() {
        addTodebugConfigOutput("=== configureWirelessConnectionWPAPSK ===");
        if (MainActivity.this.api_version >= 29) {
            configureWPAPSKAfterAPI29();
        } else {
            configureWPAPSKBeforeAPI29();
        }
    }

    public void configureWPAPSKAfterAPI29() {
        addTodebugConfigOutput("=== configureWPAPSKAfterAPI29 ===");
        final WifiNetworkSuggestion suggestion = new WifiNetworkSuggestion.Builder()
                .setSsid(MainActivity.this.ssid)
                .setIsAppInteractionRequired(false)
                .setWpa2Passphrase(MainActivity.this.password)
                .setPriority(100)
                .build();

        final List<WifiNetworkSuggestion> suggestionsList = new ArrayList<WifiNetworkSuggestion>();
        suggestionsList.add(suggestion);

        alertDialogAfterAPI29(suggestionsList);
    }

    public void configureWPAPSKBeforeAPI29() {
        addTodebugConfigOutput("=== configureWPAPSKBeforeAPI29 ===");
        WifiConfiguration wc = new WifiConfiguration();

        wc.SSID = "\"" + MainActivity.this.ssid + "\"";
        wc.hiddenSSID = false;
        wc.status = WifiConfiguration.Status.ENABLED;
        wc.priority = 40;
        wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
        wc.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
        wc.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);
        wc.preSharedKey = "\"" + MainActivity.this.password + "\"";//

        enableWifiConfiguration(wc);
    }

    /*
     * Wifi Configuration
     */
    /* Clear CONFIGURATION */
    public void clearConfiguration() {
        addTodebugConfigOutput("=== clearConfiguration ===");
        if (MainActivity.this.api_version >= 29) {
            clearConfigurationAfterAPI29();
        } else {
            clearConfigurationBeforeAPI29();
        }
    }

    public void clearConfigurationAfterAPI29() {
        addTodebugConfigOutput("=== clearConfigurationAfterAPI29 ===");
        WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        final WifiNetworkSuggestion suggestion = new WifiNetworkSuggestion.Builder()
                .setSsid(MainActivity.this.ssid)
                .setIsAppInteractionRequired(false)
                .build();

        final List<WifiNetworkSuggestion> suggestionsList = new ArrayList<WifiNetworkSuggestion>();
        suggestionsList.add(suggestion);
        final int status = wifiManager.removeNetworkSuggestions(suggestionsList);
        if (status != WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            if (MainActivity.this.isDebugMode) showNetworkError(status);
        }
    }

    public void clearConfigurationBeforeAPI29() {
        addTodebugConfigOutput("=== clearConfigurationBeforeAPI29 ===");
        List<WifiConfiguration> currentConfigurations;
        WifiManager manager = (WifiManager) MainActivity.this.getApplicationContext().getSystemService(WIFI_SERVICE);
        currentConfigurations = manager.getConfiguredNetworks();

        for (WifiConfiguration currentConfiguration : currentConfigurations) {
            if (currentConfiguration.SSID.compareToIgnoreCase(MainActivity.this.ssid) == 0) {
                manager.removeNetwork(currentConfiguration.networkId);
            }
        }
        manager.saveConfiguration();
        showInBox("Success ! Configuration Cleared for " + MainActivity.this.ssid + "!");
    }

    /* ENABLE CONFIGURATION */
    @Deprecated
    public void preparePostSuggestion() {
        addTodebugConfigOutput("=== preparePostSuggestion ===");
        BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                addTodebugConfigOutput("Connection Suggestion Succeeded before");
                String b = intent.getAction();
                addTodebugConfigOutput("Connection Suggestion Succeeded boolean " + b);
                if (!b.equals(WifiManager.ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION)) {
                    return;
                }
                addTodebugConfigOutput("Connection Suggestion Succeeded");
            }
        };
        IntentFilter intentFilter = new IntentFilter(WifiManager.ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION);
        MainActivity.this.broadcastReceiver = broadcastReceiver;
        MainActivity.this.registerReceiver(broadcastReceiver, intentFilter);
        // Note the following line is to close the receiver
        MainActivity.this.unregisterReceiver(MainActivity.this.broadcastReceiver);
    }

    public void enableWifiConfiguration(List<WifiNetworkSuggestion> suggestionsList) {
        addTodebugConfigOutput("=== enableWifiConfiguration ===");
        WifiManager wifiManager = (WifiManager) MainActivity.this.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        int status = wifiManager.addNetworkSuggestions(suggestionsList);
        if (status == WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            addTodebugConfigOutput("Suggestion Added " + MainActivity.this.ssid);
            // Note: On android 10 the startActivityResults is ending quitely on the divice:
            startActivityForResult(new Intent(Settings.ACTION_WIFI_SETTINGS), MainActivity.this.FLOW_BIB);
        } else {
            addTodebugConfigOutput("The suggestion SSID "+ MainActivity.this.ssid +" failed !");
            addTodebugConfigOutput("Status " + status);
            showNetworkError(status);
            showDebugOrExit();
        }
    }

    public static Map<String, String> getCurrentConnectionInfo(Context context) {
        Map<String, String> connectionInfo = new HashMap<String, String>();

        String ssid = null;
        ConnectivityManager connManager = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo networkInfo = connManager.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        if (networkInfo.isConnected()) {
            final WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
            final WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            if (wifiInfo != null){
                if(!TextUtils.isEmpty(wifiInfo.getSSID())) {
                    // Note: It looks that you need to request the fine location to get access to this data
                    connectionInfo.put("SSID", wifiInfo.getSSID());
                }
                if(wifiInfo.getIpAddress() != 0){
                    int ip = wifiInfo.getIpAddress();
                    connectionInfo.put("IP", String.format("%d.%d.%d.%d", (ip & 0xff), (ip >> 8 & 0xff), (ip >> 16 & 0xff), (ip >> 24 & 0xff)));
                }
            }

            SupplicantState supplicantState = wifiInfo.getSupplicantState();
            //connectionInfo.put("4WAY_HANDSHAKE",String.valueOf(supplicantState.valueOf("4WAY_HANDSHAKE")));
            connectionInfo.put("Connection completed?",String.valueOf(supplicantState.valueOf("COMPLETED")));
        }
        return connectionInfo;
    }

    public void enableWifiConfiguration(WifiConfiguration config) {
        addTodebugConfigOutput("=== enableWifiConfiguration ===");
        WifiManager wifi = (WifiManager) MainActivity.this.getApplicationContext().getSystemService(WIFI_SERVICE);

        addTodebugConfigOutput(config.toString());
        try {
            int id = wifi.addNetwork(config);
            if (id < 0) {
                addTodebugConfigOutput("Error creating new network.");
                addTodebugConfigOutput("Error: Cannot create the new network with ssid " + config.SSID);
            } else {
                addTodebugConfigOutput("Created network with ID of " + id);
                addTodebugConfigOutput("Success ! Created new network " + config.SSID + "!");
                wifi.saveConfiguration();
                wifi.enableNetwork(id, true);
            }
        } catch (Exception e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error Enable Conf:" + e.getMessage());
        }
        showDebugOrExit();
    }

    public java.security.cert.X509Certificate createX509CertFromString(String myCert) {
        java.security.cert.X509Certificate mycertificate = null;
        addTodebugConfigOutput("=== computeCaCert ===");
        InputStream is = new ByteArrayInputStream(myCert.getBytes());
        BufferedInputStream bis = new BufferedInputStream(is);

        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CC1:" + e.getMessage());
        }

        try {
            while (bis.available() > 0) {
                mycertificate = (java.security.cert.X509Certificate) cf.generateCertificate(bis);
            }
        } catch (IOException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CC2:" + e.getMessage());
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
            addTodebugConfigOutput("Error CC3:" + e.getMessage());
        }

        try {
            bis.close();
            is.close();
        } catch (IOException e) {
            // If this fails, it isn't the end of the world.
            e.printStackTrace();
            addTodebugConfigOutput("Error CC4:" + e.getMessage());
        }
        return mycertificate;
    }

}
