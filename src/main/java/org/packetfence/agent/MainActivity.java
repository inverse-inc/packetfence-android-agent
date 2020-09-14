package org.packetfence.agent;

import android.app.Activity;
import androidx.annotation.NonNull;
import android.app.AlertDialog;
import android.app.ProgressDialog;
import android.content.*;
import android.graphics.Color;
import android.net.*;
import android.net.wifi.*;
import android.net.wifi.hotspot2.PasspointConfiguration;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.security.KeyChain;
import android.text.InputType;
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
import java.io.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

public class MainActivity extends Activity {

    private static final int FLOW_CA = 20;
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
    private String caIssuer;
    private String caCrtName;
    private byte[] caCrt;
    private String ssid;
    private String tlsUsername;
    private Context context;
    private PrivateKey userPrivateKey;
    private java.security.cert.X509Certificate userCertificate;
    private java.security.cert.X509Certificate caCertificate;

    /*
     * Overrides
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
     * How to Show Information in the app
     */
    public void showInBox(String text) {
        final Activity view = this;
        Toast.makeText(view, text, Toast.LENGTH_LONG)
                .show();
    }

    /*
     * How to quit the app
     */
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
        finishAndRemoveTask();
    }


    public void showNetworkError(int iman) {
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL) {
            showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL");
            System.out.println("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED) {
            showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED");
            System.out.println("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE) {
            showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE");
            System.out.println("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP) {
            showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP");
            System.out.println("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID) {
            showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
            System.out.println("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
        }
        if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID) {
            showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
            showInBox("The " + this.ssid + " is not available.");
            System.out.println("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
        }
        // Added in API 30
        /**
         if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED){
         showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED");
         }
         if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID){
         showInBox("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID");
         }
         **/
    }

    /*
     * DIALOG
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
                    while (!done_configuring || t < 5000) {
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
        context = view.getContext();
        ByteArrayOutputStream content;
        final Activity activity = this;
        if (MainActivity.this.api_version >= 29) {
            showDialogAfterAPI29();
        } else {
            showDialogBeforeAPI29();
        }
        fetchPortalDomainName();
    }

    /*
     * TEST SECURE CONNEXION TO EXTRACT XML
     */
    public void fetchPortalDomainName() {
        if (overrideProfileUrl != null) {
            fetchXML();
            return;
        }

        final MainActivity view = this;
        DiscoveryStringRequest stringRequest = new DiscoveryStringRequest(Request.Method.GET, discoveryUrl,
                new Response.Listener<DiscoveryStringRequest.ResponseM>() {

                    @Override
                    public void onResponse(DiscoveryStringRequest.ResponseM response) {
                        showInBox("Profile domain name probe was successful");
                        try {
                            URL url = new URL(response.headers.get("Location"));
                            view.profileDomainName = url.getHost();
                            System.out.println("Found profile domain name: " + view.profileDomainName);
                            fetchXML();
                        } catch (MalformedURLException e) {
                            showInBox("Unable to detect profile domain name");
                        }
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                if (error.networkResponse == null) {
                    showInBox("Network error while finding profile domain name: " + error.getLocalizedMessage());
                } else {
                    showInBox("Error fetching profile");
                }
            }
        });
        RequestQueue queue = Volley.newRequestQueue(this);
        queue.add(stringRequest);
        MainActivity.this.done_configuring = true;
    }

    /*
     * XML PART
     */
    public void fetchXML() {
        String content;
        final Activity view = this;

        String profileUrl;
        if (this.overrideProfileUrl != null) {
            profileUrl = this.overrideProfileUrl;
        } else {
            profileUrl = this.profileProto + "://" + this.profileDomainName + this.profilePath;
        }

        StringRequest stringRequest = new StringRequest(Request.Method.GET, profileUrl,
                new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        showInBox("Downloaded profile successfully");
                        fetchXMLCallback(response);
                    }
                }, new Response.ErrorListener() {
            @Override
            public void onErrorResponse(VolleyError error) {
                if (error.networkResponse == null) {
                    showInBox("Network error: " + error.getLocalizedMessage());
                } else if (error.networkResponse.statusCode == 404) {
                    showInBox("Profile not found on server.");
                } else {
                    showInBox("Error fetching profile ");
                }
                MainActivity.this.done_configuring = true;
            }
        });
        RequestQueue queue = Volley.newRequestQueue(this);
        queue.add(stringRequest);
    }

    public void fetchXMLCallback(String content) {
        if (content != null) {
            Object[] categoryObj = parseXML(content);
            configureFromXML(categoryObj);
            Button b = (Button) findViewById(R.id.button1);
            b.setEnabled(false);
        } else {
            showInBox("Unable to fetch configuration profile.");
        }
        MainActivity.this.done_configuring = true;
    }

    public Object[] parseXML(String xml) {
        //public void parseXML(String xml) {
        Object categoryObj[] = new Object[0];
        try {
            HashMap<?, ?> hashMap = (HashMap<?, ?>) Plist.objectFromXml(xml);

            ArrayList<?> category = (ArrayList<?>) hashMap
                    .get("PayloadContent");
            this.profile = hashMap;

            categoryObj = category.toArray();
        } catch (XmlParseException e) {
            showInBox("Error PXML1:" + e.getMessage());
        }
        return categoryObj;
    }

    /*
     * WIRELESS CONFIGURATION
     */
    public void configureFromXML(Object[] categoryObj) {
        // First one contains the general configuration
        HashMap<?, ?> generalConfig = (HashMap<?, ?>) categoryObj[0];
        this.ssid = (String) generalConfig.get("SSID_STR");
        System.out.println("SSID : " + this.ssid);

        // We first clear any previous configuration for the SSID
        clearConfiguration();

        String encryptionType = (String) generalConfig
                .get("EncryptionType");

        System.out.println("encryption type : " + encryptionType);

        // Values are: WPA (PEAP, PSK), WEP
        // We first handle WEP
        if (encryptionType.equalsIgnoreCase("WEP")) {
            this.password = (String) generalConfig.get("Password");
            configureWirelessConnectionWEP();
        }
        // Now handle WPA (PEAP and PSK)
        else if (encryptionType.equalsIgnoreCase("WPA")) {
            configureWirelessConnectionWPAPEAPAndEAPTLS(categoryObj, generalConfig);
        }
    }

    /*
     * Wifi Configuration
     */
    // TODO: Check for api version
    public void clearConfiguration() {
        if (MainActivity.this.api_version >= 29) {
            //clearConfigurationAfterAPI29();
        } else {
            clearConfigurationBeforeAPI29();
        }
    }

    public void clearConfigurationAfterAPI29() {
        final WifiNetworkSuggestion suggestion = new WifiNetworkSuggestion.Builder()
                .setSsid(this.ssid)
                .setIsAppInteractionRequired(true)
                .build();

        final List<WifiNetworkSuggestion> suggestionsList = new ArrayList<WifiNetworkSuggestion>();
        suggestionsList.add(suggestion);
        final WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        final int status = wifiManager.removeNetworkSuggestions(suggestionsList);
        if (status != WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            showNetworkError(status);
        }

    }

    public void clearConfigurationBeforeAPI29() {
        List<WifiConfiguration> currentConfigurations;
        WifiManager manager;

        manager = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
        currentConfigurations = manager.getConfiguredNetworks();

        for (WifiConfiguration currentConfiguration : currentConfigurations) {
            if (currentConfiguration.SSID.compareToIgnoreCase(this.ssid) == 0) {
                manager.removeNetwork(currentConfiguration.networkId);
            }
        }
        manager.saveConfiguration();
        showInBox("Success ! Configuration Cleared for " + this.ssid + "!");
    }

    // TODO: Check for api version
    public void enableWifiConfiguration(WifiConfiguration config, boolean connect) {
        WifiManager wifi = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);

        int id = wifi.addNetwork(config);

        if (id < 0) {
            System.out.println("Error creating new network.");
            showInBox("Error: Cannot create the new network with ssid " + config.SSID);
        } else {
            System.out.println("Created network with ID of " + id);
            showInBox("Success ! Created new network " + config.SSID + "!");
        }

        showInBox("Config.networkId is " + id);

        wifi.saveConfiguration();

        if (connect) {
            wifi.enableNetwork(id, true);
        }
        this.done_configuring = true;
    }

    /*
     * Compute and transform certificates
     */
    public void computeCaCert() {
        System.out.println(MainActivity.this.caCrt);
        InputStream is = new ByteArrayInputStream(MainActivity.this.caCrt);
        BufferedInputStream bis = new BufferedInputStream(is);

        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X.509");
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
            showInBox("Error CC1:" + e.getMessage());
        }

        try {
            while (bis.available() > 0) {
                this.caCertificate = (java.security.cert.X509Certificate) cf.generateCertificate(bis);
            }
        } catch (IOException e) {
            e.printStackTrace();
            showInBox("Error CC2:" + e.getMessage());
        } catch (java.security.cert.CertificateException e) {
            e.printStackTrace();
            showInBox("Error CC3:" + e.getMessage());
        }

        try {
            bis.close();
            is.close();
        } catch (IOException e) {
            // If this fails, it isn't the end of the world.
            e.printStackTrace();
            showInBox("Error CC4:" + e.getMessage());
        }
    }

    public void computeUserCertAndKey() {
        KeyStore p12 = null;
        try {
            p12 = KeyStore.getInstance("pkcs12");
            try {
                p12.load(new ByteArrayInputStream(this.userP12), this.password.toCharArray());
            } catch (IOException e) {
                e.printStackTrace();
                showInBox("Error CK1:" + e.getMessage());
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
                showInBox("Error CK2:" + e.getMessage());
            } catch (CertificateException e) {
                e.printStackTrace();
                showInBox("Error CK3:" + e.getMessage());
            }

            Enumeration e = p12.aliases();
            while (e.hasMoreElements()) {
                String alias = (String) e.nextElement();
                this.userCertificate = (java.security.cert.X509Certificate) p12.getCertificate(alias);
                this.userPrivateKey = (PrivateKey) p12.getKey(alias, this.password.toCharArray());

                // We are not using the code below
                Principal subject = this.userCertificate.getSubjectDN();
                String subjectArray[] = subject.toString().split(",");
                for (String s : subjectArray) {
                    String[] str = s.trim().split("=");
                    if (str.length >= 2) {
                        String key = str[0];
                        String value = str[1];
                        System.out.println(key + " - " + value);
                    }
                }
                // TODO: what is it for ?
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
            showInBox("Error CK4:" + e.getMessage());
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            showInBox("Error CK5:" + e.getMessage());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            showInBox("Error CK6:" + e.getMessage());
        }
    }

    /*
     * Wireless Configurations WEP
     */
    public void configureWirelessConnectionWEP() {
        // Check the api version
        if (MainActivity.this.api_version >= 29) {
            configureWEPAfterAPI29();
        } else if (MainActivity.this.api_version < 29) {
            configureWEPBeforeAPI29();
        }
    }

    // TODO: Change it for api 29 currently equal to before 29
    public void configureWEPAfterAPI29() {

    }

    public void configureWEPBeforeAPI29() {
        String ssid = this.ssid;
        String psk = this.password;

        try {
            WifiConfiguration wc = new WifiConfiguration();

            wc.SSID = "\"" + ssid + "\"";
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

            wc.wepKeys[0] = "\"" + psk + "\"";//
            wc.wepTxKeyIndex = 0;

            System.out.println("ssid : " + wc.SSID);

            enableWifiConfiguration(wc, true);

        } catch (Exception e) {
            showInBox("error:" + e.getMessage());
        }
    }

    /*
     * Wireless Configurations WPA-PEAP And EAP-TLS
     */
    public void configureWirelessConnectionWPAPEAPAndEAPTLS(Object[] categoryObj, HashMap<?, ?> generalConfig) {
        HashMap<?, ?> eapClientConfigurationHashMap = (HashMap<?, ?>) generalConfig
                .get("EAPClientConfiguration");

        // Handling WPA-PEAP and EAP-TLS
        if (eapClientConfigurationHashMap != null) {
            System.out.println("Detected WPA EAP configuration");
            ArrayList<?> eapTypes = (ArrayList<?>) eapClientConfigurationHashMap
                    .get("AcceptEAPTypes");

            if (eapTypes.contains(Integer.valueOf(EAPTYPE_TLS))) {
                System.out.println("Detected WPA EAP-TLS configuration");

                // We skip the first section
                for (int i = 1; i < categoryObj.length; i++) {
                    HashMap<?, ?> config = (HashMap<?, ?>) categoryObj[i];
                    String payloadType = (String) (config.get("PayloadType"));
                    if (payloadType.equals("com.apple.security.root")) {
                        System.out.println("Found root certificate");
                        String caBytes = (String) config.get("PayloadContent");

                        String caCrtNoHead = new String(caBytes);
                        String caCrtStr = "";
                        caCrtStr += "-----BEGIN CERTIFICATE-----\n";
                        caCrtStr += caCrtNoHead;
                        caCrtStr += "\n" +
                                "-----END CERTIFICATE-----";

                        MainActivity.this.caCrt = caCrtStr.getBytes();
                        System.out.println("this.caCrt");
                        System.out.println(this.caCrt);
                        MainActivity.this.caCrtName = (String) config.get("PayloadIdentifier");
                        MainActivity.this.caCrtName = MainActivity.this.caCrtName.replace('.', '-');
                    }
                    if (payloadType.equals("com.apple.security.pkcs12")) {
                        System.out.println("Found the EAP-TLS p12 certificate");
                        String p12BytesB64 = (String) config.get("PayloadContent");
                        byte[] p12Bytes = Base64.decode(p12BytesB64.getBytes(), Base64.DEFAULT);

                        this.userP12 = p12Bytes;
                        this.userP12Name = (String) config.get("PayloadDisplayName");
                        this.tlsUsername = (String) config.get("PayloadCertificateFileName");
                    }
                }
                configureWirelessConnectionWPA2TLS();

            } else if (eapTypes.contains(Integer.valueOf(EAPTYPE_PEAP))) {
                System.out.println("Detected WPA EAP-PEAP configuration");
                this.tlsUsername = (String) eapClientConfigurationHashMap
                        .get("UserName");
                configureWirelessConnectionWPA2PEAP();
            }
        }
        // Handling WPA-PSK
        else {
            this.password = (String) generalConfig.get("Password");
            configureWirelessConnectionWPAPSK();
        }

    }

    /* WPA2TLS */
    public void configureWirelessConnectionWPA2TLS() {
        AlertDialog.Builder alert = new AlertDialog.Builder(this);
        alert.setTitle("Certificate password");
        alert.setMessage("Enter the password to unlock your certificate.");
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        alert.setView(input);
        alert.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                MainActivity.this.password = input.getText().toString();
                computeCaCert();
                computeUserCertAndKey();
                if (MainActivity.this.api_version >= 29) {
                    configureWPA2TLSAfterAPI29();
                } else if (MainActivity.this.api_version > 19 && MainActivity.this.api_version < 25) {
                    configureWPA2TLSAPI20();
                } else {
                    configureWPA2TLSBeforeAPI29();
                }
            }
        });
        alert.show();
    }

    public void configureWPA2TLSAfterAPI29() {

    }

    public void configureWPA2TLSBeforeAPI29() {
        WifiManager mWifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);

        WifiConfiguration mWifiConfig = new WifiConfiguration();
        WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();

        /*Key Mgmnt*/
        mWifiConfig.allowedKeyManagement.clear();
        mWifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
        mWifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        /*Group Ciphers*/
        mWifiConfig.allowedGroupCiphers.clear();
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

        /*Pairwise ciphers*/
        mWifiConfig.allowedPairwiseCiphers.clear();
        mWifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        mWifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

        /*Protocols*/
        mWifiConfig.allowedProtocols.clear();
        mWifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        mWifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);


        mWifiConfig.networkId = -1;
        mWifiConfig.SSID = '"' + this.ssid + '"';
        mWifiConfig.enterpriseConfig = mEnterpriseConfig;

        mEnterpriseConfig.setIdentity(this.tlsUsername);
        mEnterpriseConfig.setPassword("test");
        mEnterpriseConfig.setCaCertificate(this.caCertificate);
        mEnterpriseConfig.setClientKeyEntry(this.userPrivateKey, this.userCertificate);

        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.NONE);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.TLS);

        System.out.println(mWifiConfig.toString());
        System.out.println(this.userPrivateKey.toString());
        System.out.println(this.userCertificate.toString());

        enableWifiConfiguration(mWifiConfig, true);

    }

    public void configureWPA2TLSAPI20() {
        String displayName = this.userP12Name;
        byte[] certificate = this.caCrt;
        int FLOW_CODE = this.FLOW_CA;

        Intent installIntent = KeyChain.createInstallIntent();
        installIntent.putExtra(KeyChain.EXTRA_NAME, displayName);
        try {
            X509Certificate x509 = X509Certificate.getInstance(certificate);
            this.caIssuer = x509.getIssuerDN().getName();
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, x509.getEncoded());
        } catch (Exception e) {
            showInBox("error while parsing certificate:" + e.getMessage());
        }
        startActivityForResult(installIntent, FLOW_CODE);
    }

    // Not needed any more
    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == FLOW_CA) {
            configureWPA2TLSBeforeAPI29();
        }
    }

    /* WPA2PEAP */
    // TODO: Check for api version
    public void configureWirelessConnectionWPA2PEAP() {
        AlertDialog.Builder alert = new AlertDialog.Builder(this);
        alert.setTitle("User password");
        if (this.tlsUsername != null || this.tlsUsername.trim().length() > 0) {
            alert.setMessage("Enter password for " + this.tlsUsername);
        }
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        alert.setView(input);
        alert.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                MainActivity.this.password = input.getText().toString();
                if (MainActivity.this.api_version >= 29) {
                    // https://stackoverflow.com/questions/4374862/how-to-programmatically-create-and-read-wep-eap-wifi-configurations-in-android/4374934
                    // https://stackoverflow.com/questions/59711493/how-to-connect-wifi-using-ssid-and-password-in-android-q
                    // https://stackoverflow.com/questions/32083410/cant-get-write-settings-permission/49850704
                    // https://stackoverflow.com/questions/56905956/is-it-possible-to-add-a-network-configuration-on-android-q
                    // https://stackoverflow.com/questions/58769623/android-10-api-29-how-to-connect-the-phone-to-a-configured-network
                    configureWPA2PEAPAfterAPI29_11();
                    //configureWPA2PEAPAfterAPI29_21();
                } else {
                    configureWPA2PEAPBeforeAPI29();
                }
            }
        });
        alert.show();
    }

    public void configureWPA2PEAPAfterAPI29_11() {
        final WifiNetworkSuggestion suggestion1 = new WifiNetworkSuggestion.Builder()
                .setSsid(ssid)
                .setWpa2Passphrase(password)
                .setIsAppInteractionRequired(true)
                .build();

        final List<WifiNetworkSuggestion> suggestionsList = new ArrayList<WifiNetworkSuggestion>();
        suggestionsList.add(suggestion1);
        final WifiManager wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        final int status = wifiManager.addNetworkSuggestions(suggestionsList);

        if (status != WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
            showNetworkError(status);
        }

        final IntentFilter intentFilter = new IntentFilter(WifiManager.ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION);

        final BroadcastReceiver broadcastReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context context, Intent intent) {
                if (!intent.getAction().equals(WifiManager.ACTION_WIFI_NETWORK_SUGGESTION_POST_CONNECTION)) {
                    return;
                }
            }
        };
        getApplicationContext().registerReceiver(broadcastReceiver, intentFilter);

    }
    public void configureWPA2PEAPAfterAPI29_21() {
        WifiNetworkSpecifier wifiNetworkSpecifier = new WifiNetworkSpecifier.Builder()
                .setSsid(ssid)
                .setWpa2Passphrase(password)
                .build();
        NetworkRequest networkRequest = new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .setNetworkSpecifier(wifiNetworkSpecifier)
                .build();
        ConnectivityManager connectivityManager = (ConnectivityManager)this.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
        connectivityManager.requestNetwork(networkRequest, new ConnectivityManager.NetworkCallback());
    }

    public void configureWPA2PEAPAfterAPI29_22() {
        WifiNetworkSpecifier.Builder builder = new WifiNetworkSpecifier.Builder();
        builder.setSsid(ssid);
        builder.setWpa2Passphrase(password);

        try {
            WifiNetworkSpecifier wifiNetworkSpecifier = builder.build();

            NetworkRequest.Builder networkRequestBuilder = new NetworkRequest.Builder();
            networkRequestBuilder.addTransportType(NetworkCapabilities.TRANSPORT_WIFI);
            networkRequestBuilder.removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
            networkRequestBuilder.setNetworkSpecifier(wifiNetworkSpecifier);
            NetworkRequest networkRequest = networkRequestBuilder.build();

            final ConnectivityManager cm = (ConnectivityManager) this.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);

            ConnectivityManager.NetworkCallback networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull Network network) {
                    super.onAvailable(network);
                    cm.bindProcessToNetwork(network);
                }
            };
            cm.requestNetwork(networkRequest, networkCallback);

        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }
    }

    public void configureWPA2PEAPAfterAPI29_23() {
        WifiNetworkSpecifier wifiNetworkSpecifier = new WifiNetworkSpecifier.Builder()
                .setSsid(this.ssid)
                .setWpa2Passphrase(this.password)
                .build();

        NetworkRequest networkRequest = new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .setNetworkSpecifier(wifiNetworkSpecifier)
                .build();
        try {
            ConnectivityManager connectivityManager = (ConnectivityManager) this.getApplicationContext().getSystemService(Context.CONNECTIVITY_SERVICE);
            connectivityManager.requestNetwork(networkRequest, new ConnectivityManager.NetworkCallback());
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }
        this.done_configuring = true;
    }

    public void configureWPA2PEAPBeforeAPI29() {
        System.out.println("Configuring " + this.ssid + " with username " + this.tlsUsername + " and password " + this.password);

        WifiManager mWifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);

        WifiConfiguration mWifiConfig = new WifiConfiguration();
        WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();

        /*Key Mgmnt*/
        mWifiConfig.allowedKeyManagement.clear();
        mWifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
        mWifiConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

        /*Group Ciphers*/
        mWifiConfig.allowedGroupCiphers.clear();
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
        mWifiConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

        /*Pairwise ciphers*/
        mWifiConfig.allowedPairwiseCiphers.clear();
        mWifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
        mWifiConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

        /*Protocols*/
        mWifiConfig.allowedProtocols.clear();
        mWifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
        mWifiConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);


        mWifiConfig.networkId = -1;
        mWifiConfig.SSID = '"' + this.ssid + '"';
        mWifiConfig.enterpriseConfig = mEnterpriseConfig;

        mEnterpriseConfig.setIdentity(this.tlsUsername);
        mEnterpriseConfig.setAnonymousIdentity(this.tlsUsername);
        mEnterpriseConfig.setPassword(this.password);

        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.MSCHAPV2);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.PEAP);

        System.out.println(mWifiConfig.toString());

        enableWifiConfiguration(mWifiConfig, true);
    }

    /* WPAPSK */
    // TODO: Check for api version
    public void configureWirelessConnectionWPAPSK() {
        if (MainActivity.this.api_version >= 29) {
            configureWPAPSKAfterAPI29();
        } else {
            configureWPAPSKBeforeAPI29();
        }
    }

    public void configureWPAPSKAfterAPI29() {

    }

    public void configureWPAPSKBeforeAPI29() {

        try {
            WifiConfiguration wc = new WifiConfiguration();

            wc.SSID = "\"" + this.ssid + "\"";
            wc.hiddenSSID = false;
            wc.status = WifiConfiguration.Status.ENABLED;
            wc.priority = 40;
            wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
            wc.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

            wc.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

            wc.preSharedKey = "\"" + this.password + "\"";//

            System.out.println("ssid : " + wc.SSID);

            enableWifiConfiguration(wc, true);

        } catch (Exception e) {
            showInBox("error:" + e.getMessage());
        }
    }

}
