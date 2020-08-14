package org.packetfence.agent;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.BitSet;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiEnterpriseConfig;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiNetworkSpecifier;
import android.net.NetworkSpecifier;
import android.net.NetworkRequest;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Bundle;
import android.app.Activity;
//import android.app.ProgressDialog;
import android.os.Looper;
import android.text.InputType;
import android.util.Base64;
import android.view.Menu;
import android.view.View;
import android.graphics.Color;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import xmlwise.*;
import android.security.KeyChain;
import android.widget.ProgressBar;
import android.widget.LinearLayout;
import android.view.ViewGroup;
import android.widget.TextView;
import android.view.Gravity;
import android.view.Window;
import android.view.WindowManager;
import android.net.wifi.WifiNetworkSuggestion;
import android.os.Handler;

import com.android.volley.Request;
import com.android.volley.RequestQueue;
import com.android.volley.Response;
import com.android.volley.VolleyError;
import com.android.volley.toolbox.StringRequest;
import com.android.volley.toolbox.Volley;

import javax.security.cert.X509Certificate;

public class MainActivity extends Activity {

	public static String profileUrl = "https://wireless-profiles.packetfence.org/profile.xml";

	public static int EAPTYPE_TLS = 13;
	public static int EAPTYPE_LEAP = 17;
	public static int EAPTYPE_TTLS = 21;
	public static int EAPTYPE_PEAP = 25;
	public static int EAPTYPE_EAP_FAST = 43;
	public static boolean done_configuring = false;
	public static boolean done_install_certificate = false;
	private HashMap profile;
	private String userP12Name;
	private byte[] userP12;
	private String userP12Pass;
	private String caIssuer;
	private String caCrtName;
	private byte[] caCrt;
	private String tlsSSID;
	private String tlsUsername;
	private Context context;

	private PrivateKey userPrivateKey;
	private java.security.cert.X509Certificate userCertificate;
	private java.security.cert.X509Certificate caCertificate;

	private static final int FLOW_CA = 20;

	private static final int api_version = Build.VERSION.SDK_INT;

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
	 * How to Show informations in the app
	 */
	public void show_in_box(String sbox){
		final Activity view = this;
		Toast.makeText(view, sbox, Toast.LENGTH_LONG)
				.show();
	}

	public static void showFor(final Toast aToast, final long durationInMilliseconds) {
		aToast.setDuration(Toast.LENGTH_SHORT);
		Thread t = new Thread() {
			long timeElapsed = 0l;
			public void run() {
				try {
					while (timeElapsed <= durationInMilliseconds) {
						long start = System.currentTimeMillis();
						aToast.show();
						sleep(1750);
						timeElapsed += System.currentTimeMillis() - start;
					}
				} catch (InterruptedException e) {
				}
			}
		};
		t.start();
	}

	public void show_in_box_for(String sbox,int howlong){
		Toast aToast = Toast.makeText(this, sbox, Toast.LENGTH_SHORT);
		showFor(aToast, howlong);
	}

	public void show_network_error(int iman){
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_INTERNAL");
		}
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_APP_DISALLOWED");
		}
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_DUPLICATE");
		}
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_EXCEEDS_MAX_PER_APP");
		}
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
		}
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_REMOVE_INVALID");
		}
		// Added in API 30
		/**
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_NOT_ALLOWED");
		}
		if (iman == WifiManager.STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID){
			show_in_box("network_error STATUS_NETWORK_SUGGESTIONS_ERROR_ADD_INVALID");
		}
		**/
	}




	/*
	 * How to quit the app
	 */
	public void quit(View view) {
		System.exit(0);
	}

	public void stop_application_in_seconds(int sec){
		int inum = sec*1000;
		Long lnum = Long.valueOf(inum);
		Handler handler = new Handler();
		handler.postDelayed(new Runnable() {public void run() {}},lnum);
		finishAndRemoveTask();
	}




	/*
	 * Source: https://stackoverflow.com/a/49272722
	 */
	public AlertDialog setProgressDialog() {
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

		AlertDialog dialog = builder.create();
		dialog.show();
		Window window = dialog.getWindow();
		if (window != null) {
			WindowManager.LayoutParams layoutParams = new WindowManager.LayoutParams();
			layoutParams.copyFrom(dialog.getWindow().getAttributes());
			layoutParams.width = LinearLayout.LayoutParams.WRAP_CONTENT;
			layoutParams.height = LinearLayout.LayoutParams.WRAP_CONTENT;
			dialog.getWindow().setAttributes(layoutParams);
		}
		return dialog;
	}




	/*
	 * Main Application
	 */
	/* Configure */
	public void configure(View view) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException {
		context = view.getContext();
		ByteArrayOutputStream content;
        final Activity activity = this;
		final AlertDialog dial = setProgressDialog();
		
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
				dial.dismiss();
			}
		}).start();
		fetchXML();
	}

	/* XML Fetch */
	public void fetchXML() {
		NukeSSLCerts.nuke();
		StringRequest stringRequest = new StringRequest(Request.Method.GET, profileUrl,
				new Response.Listener<String>() {
					@Override
					public void onResponse(String response) {
						show_in_box("Downloaded profile successfully");
						fetchXMLCallback(response);
					}
				}, new Response.ErrorListener() {
			@Override
			public void onErrorResponse(VolleyError error) {
				if(error.networkResponse == null) {
					show_in_box("Network error: " + error.getLocalizedMessage());
				}
				else if(error.networkResponse.statusCode == 404) {
					show_in_box("Profile not found on server.");
				}
				else {
					show_in_box("Error fetching profile ");
				}
				stop_application_in_seconds(5);
			}
		});
		RequestQueue queue = Volley.newRequestQueue(this);
		queue.add(stringRequest);
	}

	/* XML Fetch Call From Button */
	public void fetchXMLCallback(String content) {
		if (content != null) {
			parseXML(content);
			Button b = (Button) findViewById(R.id.button1);
			b.setEnabled(true);
		} else {
			show_in_box("Unable to fetch configuration profile.");
            done_configuring = true;
			stop_application_in_seconds(5);
		}
	}

	/* XML Parse and configure */
	// This one should be divided in parsing then configuration
	public void parseXML(String xml) {
		try {
			HashMap<?, ?> hashMap = (HashMap<?, ?>) Plist.objectFromXml(xml);

			ArrayList<?> category = (ArrayList<?>) hashMap
					.get("PayloadContent");
			this.profile = hashMap; // only used here

			Object categoryObj[];
			categoryObj = category.toArray();

			// First one contains the general configuration
			HashMap<?, ?> generalConfig = (HashMap<?, ?>) categoryObj[0];

			String ssid = (String) generalConfig.get("SSID_STR");

			System.out.println("SSID : "+ssid);
			//show_in_box("SSID: " + ssid);

			// We first clear any previous configuration for the SSID
			if(api_version > 29) {
				show_in_box("api_version: " + api_version);
				clearConfiguration(ssid);
			} else {
				show_in_box("api_version: " + api_version);
				clearConfiguration_old(ssid);
			}
			String encryptionType = (String) generalConfig
					.get("EncryptionType");

			System.out.println("encryption type : "+encryptionType);
			//show_in_box("encryptionType: " + encryptionType);

			//
			// Values are: WPA (PEAP, PSK), WEP
			//
			// We first handle WEP
			if (encryptionType.equalsIgnoreCase("WEP")) {
				String psk = (String) generalConfig.get("Password");
				configureWirelessConnectionWEP(ssid, psk);
			}
			// Now handle WPA (PEAP and PSK)
			else if (encryptionType.equalsIgnoreCase("WPA")) {
				HashMap<?, ?> eapClientConfigurationHashMap = (HashMap<?, ?>) generalConfig
						.get("EAPClientConfiguration");

				// Handling WPA-PEAP and EAP-TLS
				if (eapClientConfigurationHashMap != null) {
					System.out.println("Detected WPA EAP configuration");
					ArrayList<?> eapTypes = (ArrayList<?>) eapClientConfigurationHashMap
							.get("AcceptEAPTypes");

					if(eapTypes.contains(Integer.valueOf(EAPTYPE_TLS))){
						System.out.println("Detected WPA EAP-TLS configuration");
						//show_in_box("Detected WPA EAP-TLS configuration");

						// We skip the first section
						for (int i = 1; i < categoryObj.length; i++) {
							HashMap<?, ?> config = (HashMap<?, ?>) categoryObj[i];
							String payloadType = (String)(config.get("PayloadType"));
							if ( payloadType.equals("com.apple.security.root")){
								System.out.println("Found root certificate");
								//show_in_box("Found root certificate");
								String caBytes = (String)config.get("PayloadContent");

								String caCrtNoHead = new String(caBytes);
								String caCrtStr = "";
								caCrtStr += "-----BEGIN CERTIFICATE-----\n";
								caCrtStr += caCrtNoHead;
								caCrtStr += "\n" +
										"-----END CERTIFICATE-----";

								this.caCrt = caCrtStr.getBytes();
								this.caCrtName = (String) config.get("PayloadIdentifier");
								this.caCrtName = this.caCrtName.replace('.', '-');
							}
							if( payloadType.equals("com.apple.security.pkcs12")){
								System.out.println("Found the EAP-TLS p12 certificate");
								//show_in_box("Found the EAP-TLS p12 certificate");
								String p12BytesB64 = (String)config.get("PayloadContent");
								byte[] p12Bytes = Base64.decode(p12BytesB64.getBytes(), Base64.DEFAULT);

								this.userP12 = p12Bytes;
								this.userP12Name = (String) config.get("PayloadDisplayName");
								this.tlsUsername = (String) config.get("PayloadCertificateFileName");
								this.tlsSSID = ssid;
							}
						}

						if(api_version > 28) {
							show_in_box("Install p12 certificates for api > 29");
							// Next step will be to prepare the ssid
							installp12CertificatesWithPrompt();
							// computeUserCertAndKey(); // This one is not working because it needs password.
							computeCaCert();
							if (done_install_certificate){
								show_in_box("P12 certificates are installed");
							}
						} else {
							//parsing done we fire the cert install
							//the rest of the flow is handled by callbacks after the activities
							//looks like Android is a wanabe Javascript
							// We do not see done_configuring here as the callback will do it for us
							promptCertPassword();
							computeCertificates();
							if (api_version > 19 && api_version < 29) {
								// On Android 5 we make the user install the certificate to unlock access to the storage
								// This will callback to the configuration of the TLS profile
								// (kind of Javascript in Java) - Android is evil
								show_in_box("Only CA certificate is installed");
								installCaCertificate();
								if (done_install_certificate){
									show_in_box("Ca certificate is installed");
								}
							}
						}
						// If the certificates are well installed then configure the ssid
						configureWirelessConnectionWPA2TLS(tlsSSID, tlsUsername);
					}
					else if (eapTypes.contains(Integer.valueOf(EAPTYPE_PEAP))) {
						System.out.println("Detected WPA EAP-PEAP configuration");
						String username = (String) eapClientConfigurationHashMap
								.get("UserName");

                        if(username != null || username.trim().length() > 0) {
                            promptUsernamePasswordAndConfigurePEAP(ssid, username);
                        }
                        else {
                            configureWirelessConnectionWPA2PEAP(ssid, username, "");
                        }
					}
				}
				// Handling WPA-PSK
				else {
					String psk = (String) generalConfig.get("Password");
					configureWirelessConnectionWPAPSK(ssid, psk);
				}
			}

		} catch (XmlParseException e) {
			show_in_box("error:" + e.getMessage());
		}
		done_configuring = true;
	}




	/*
	 * Functions to compute Ca / P12 Certificates
	 */
	public void promptCertPassword() {
		AlertDialog.Builder alert = new AlertDialog.Builder(this);

		alert.setTitle("Certificate password");
		alert.setMessage("Enter the password to unlock your certificate.");

		// Set an EditText view to get user input
		final EditText input = new EditText(this);
		alert.setView(input);

		alert.setPositiveButton("Ok", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				MainActivity.this.userP12Pass = input.getText().toString();
			}
		});
		alert.show();
	}

	private void computeCertificates() {
		computeCaCert();
		computeUserCertAndKey();
	}

	public void computeUserCertAndKey() {
		KeyStore p12 = null;
		try {
			p12 = KeyStore.getInstance("pkcs12");
			try {
				p12.load(new ByteArrayInputStream(this.userP12), this.userP12Pass.toCharArray());
				//show_in_box("P12 is extracted");
			} catch (IOException e) {
				e.printStackTrace();
				show_in_box("error:" + e.getMessage());
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
				show_in_box("error:" + e.getMessage());
			} catch (CertificateException e) {
				e.printStackTrace();
				show_in_box("error:" + e.getMessage());
			}

			Enumeration e = p12.aliases();
			while (e.hasMoreElements()) {
				String alias = (String) e.nextElement();
				this.userCertificate = (java.security.cert.X509Certificate) p12.getCertificate(alias);
				this.userPrivateKey = (PrivateKey)p12.getKey(alias, this.userP12Pass.toCharArray());
				//show_in_box_for("userPrivateKey " + userPrivateKey, 55000);
				Principal subject = this.userCertificate.getSubjectDN();
				String subjectArray[] = subject.toString().split(",");
				for (String s : subjectArray) {
					String[] str = s.trim().split("=");
					if(str.length >= 2) {
						String key = str[0];
						String value = str[1];
						System.out.println(key + " - " + value);
					}
				}
			}
		} catch (KeyStoreException e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		}
	}

	public void computeCaCert()
	{
		InputStream is = new ByteArrayInputStream(caCrt);
		BufferedInputStream bis = new BufferedInputStream(is);
		CertificateFactory cf = null;

		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (java.security.cert.CertificateException e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		}

		try {
			while (bis.available() > 0) {
				this.caCertificate = (java.security.cert.X509Certificate) cf.generateCertificate(bis);
			}
		} catch (IOException e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		} catch (java.security.cert.CertificateException e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		}

		try {
			bis.close();
			is.close();
		} catch (IOException e) {
			// If this fails, it isn't the end of the world.
			e.printStackTrace();
		}
	}

	/*
	 * Functions to install Ca / P12 Certificates
	 */
	private void installp12CertificatesWithPrompt(){
		installCertificate(this.userP12Name, this.userP12, true, FLOW_CA);
	}

	private void installCaCertificate(){
		installCertificate(this.caCrtName, this.caCrt, false, FLOW_CA);
	}

	public void installCertificate(String displayName, byte[] certificate, boolean isPkcs12, int FLOW_CODE){
		Intent installIntent = KeyChain.createInstallIntent();
		try {
			if(isPkcs12){
				installIntent.putExtra(KeyChain.EXTRA_PKCS12, certificate);
			}
			else {
				X509Certificate x509 = X509Certificate.getInstance(certificate);
				caIssuer = x509.getIssuerDN().getName();
				installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, x509.getEncoded());
			}
		}
		catch(Exception e){
			show_in_box("Error while parsing certificate");
		}
		installIntent.putExtra(KeyChain.EXTRA_NAME, displayName);
		startActivityForResult(installIntent, FLOW_CODE);
	}

	/* Set done_install_certificate to true, if the certificate is installed */
	@Override
	protected void onActivityResult(int requestCode, int resultCode, Intent data)
	{
		if(requestCode == FLOW_CA){
			// This should be there because it is already in line 326
			//configureWirelessConnectionWPA2TLS(this.tlsSSID, this.tlsUsername);
			done_install_certificate = true;
		}
	}




	/*
	 * Configurations
	 */
	/* Clean configuration */
	// Since API 29, there is a modification on the way to create or delete a ssid config network
	public void clearConfiguration (String ssid) {
		WifiManager manager = (WifiManager) getSystemService(Context.WIFI_SERVICE);
		WifiNetworkSuggestion.Builder builder = new WifiNetworkSuggestion.Builder()
				.setSsid(ssid);
		WifiNetworkSuggestion suggestion = builder.build();
		List<WifiNetworkSuggestion> networkSuggestions = new ArrayList<WifiNetworkSuggestion>();
		networkSuggestions.add(suggestion);
		int iman = manager.removeNetworkSuggestions(networkSuggestions);

		if (iman != WifiManager.STATUS_NETWORK_SUGGESTIONS_SUCCESS) {
			System.out.println("Network Error Config "+String.valueOf(iman));
			show_in_box("clear configuration failed");
			show_network_error(iman);
		} else {
			show_in_box("clear configuration done");
		}
	}
	// For API before 29 and perhaps between two others
	public void clearConfiguration_old (String ssid) {
		List<WifiConfiguration> currentConfigurations;
		WifiManager manager;

		manager = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
		currentConfigurations = manager.getConfiguredNetworks();

		for (WifiConfiguration currentConfiguration : currentConfigurations) {
			if (currentConfiguration.SSID.compareToIgnoreCase(ssid) == 0) {
				manager.removeNetwork(currentConfiguration.networkId);
			}
		}
		manager.saveConfiguration();
	}
	/* Start Wifi configuration */
	public void enableWifiConfiguration(WifiConfiguration config, boolean connect) {
		WifiManager wifi = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);

		int id = wifi.addNetwork(config);
		if (id < 0) {
			System.out.println("Error creating new network.");
			show_in_box("error: Cannot create the new network");
		} else {
			System.out.println("Created network with ID of " + id);
			show_in_box("Success ! Created new network "+config.SSID+"!");
		}

		if (connect) {
			wifi.enableNetwork(id, false);
		}

		wifi.saveConfiguration();

		if (connect) {
			wifi.enableNetwork(id, true);
		}
	}




	/*
	 * Wireless Configurations
	 */
	/* WEP */
	public void configureWirelessConnectionWEP(String ssid, String psk) {
		
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
			show_in_box("error:" + e.getMessage());
		}
	}
	
	/* WPAPSK */
	public void configureWirelessConnectionWPAPSK(String ssid, String psk) {

		try {
			WifiConfiguration wc = new WifiConfiguration();

			wc.SSID = "\"" + ssid + "\"";
			wc.hiddenSSID = false;
			wc.status = WifiConfiguration.Status.ENABLED;
			wc.priority = 40;
			wc.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_PSK);
			wc.allowedProtocols.set(WifiConfiguration.Protocol.WPA);

			wc.allowedAuthAlgorithms.set(WifiConfiguration.AuthAlgorithm.OPEN);

			wc.preSharedKey = "\"" + psk + "\"";//

			System.out.println("ssid : " + wc.SSID);

			enableWifiConfiguration(wc, true);
		} catch (Exception e) {
			show_in_box("error:" + e.getMessage());
		}
	}

	/* PEAP */
    public void promptUsernamePasswordAndConfigurePEAP(final String ssid, final String username) {
        AlertDialog.Builder alert = new AlertDialog.Builder(this);

        alert.setTitle("Enter password for "+username);
        //alert.setMessage("Enter password for : "+username);

        // Set an EditText view to get user input
        final EditText input = new EditText(this);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        alert.setView(input);

        alert.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                String password = input.getText().toString();
                configureWirelessConnectionWPA2PEAP(ssid, username, password);
            }
        });

        alert.show();
    }

	/* WPA2TLS */
	public void configureWirelessConnectionWPA2TLS(String ssid, String username){
		WifiManager mWifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);

		WifiConfiguration mWifiConfig = new WifiConfiguration();
		WifiEnterpriseConfig mEnterpriseConfig = new WifiEnterpriseConfig();

		if(userPrivateKey == null || userCertificate == null || caCertificate == null){
			show_in_box("error: There was an error retrieving the certificates");
		}

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
		mWifiConfig.SSID = '"'+ssid+'"';
		mWifiConfig.enterpriseConfig = mEnterpriseConfig;

		mEnterpriseConfig.setIdentity(username);
		mEnterpriseConfig.setPassword("test");
		mEnterpriseConfig.setCaCertificate(this.caCertificate);
		mEnterpriseConfig.setClientKeyEntry(this.userPrivateKey, this.userCertificate);

		mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.NONE);
		mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.TLS);

		System.out.println(mWifiConfig.toString());

		enableWifiConfiguration(mWifiConfig, true);
	}

	/* WPA2PEAP */
	public void configureWirelessConnectionWPA2PEAP(String ssid, String username, String password){
        System.out.println("Configuring " + ssid + " with username " + username + " and password " + password);

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
        mWifiConfig.SSID = '"'+ssid+'"';
        mWifiConfig.enterpriseConfig = mEnterpriseConfig;

        mEnterpriseConfig.setIdentity(username);
        mEnterpriseConfig.setAnonymousIdentity(username);
        mEnterpriseConfig.setPassword(password);

        mEnterpriseConfig.setPhase2Method(WifiEnterpriseConfig.Phase2.MSCHAPV2);
        mEnterpriseConfig.setEapMethod(WifiEnterpriseConfig.Eap.PEAP);

        System.out.println(mWifiConfig.toString());

        enableWifiConfiguration(mWifiConfig, true);
    }

	/* WPA2PEAPOLD */
	public void configureWirelessConnectionWPA2PEAPOLD(String ssid,
			String userName, String password) {

		final String INT_PRIVATE_KEY = "private_key";
		final String INT_PHASE2 = "phase2";
		final String INT_PASSWORD = "password";
		final String INT_IDENTITY = "identity";
		final String INT_EAP = "eap";
		final String INT_CLIENT_CERT = "client_cert";
		final String INT_CA_CERT = "ca_cert";
		final String INT_ANONYMOUS_IDENTITY = "anonymous_identity";
		final String INT_ENTERPRISEFIELD_NAME = "android.net.wifi.WifiConfiguration$EnterpriseField";

		// connection properties
		final String ENTERPRISE_EAP = "PEAP";
		final String ENTERPRISE_PHASE2 = "MSCHAPV2";  // Nothing for MSCHAPv2
		final String ENTERPRISE_CLIENT_CERT = "";
		final String ENTERPRISE_PRIV_KEY = "";
		final String ENTERPRISE_ANON_IDENT = "";
		
		WifiConfiguration selectedConfig = new WifiConfiguration();

		selectedConfig.BSSID = null;
		selectedConfig.SSID = "\"" + ssid + "\"";
		selectedConfig.priority = 40;
		selectedConfig.hiddenSSID = false;
		selectedConfig.status = WifiConfiguration.Status.DISABLED;
		 
		selectedConfig.allowedKeyManagement.clear();
		selectedConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.IEEE8021X);
		selectedConfig.allowedKeyManagement.set(WifiConfiguration.KeyMgmt.WPA_EAP);

		selectedConfig.allowedGroupCiphers.clear();
		selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.CCMP);
		selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.TKIP);
		selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP104);
		selectedConfig.allowedGroupCiphers.set(WifiConfiguration.GroupCipher.WEP40);

		selectedConfig.allowedPairwiseCiphers.clear();
		selectedConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.CCMP);
		selectedConfig.allowedPairwiseCiphers.set(WifiConfiguration.PairwiseCipher.TKIP);

		selectedConfig.allowedProtocols.clear();
		selectedConfig.allowedProtocols.set(WifiConfiguration.Protocol.RSN);
		selectedConfig.allowedProtocols.set(WifiConfiguration.Protocol.WPA);
		
		selectedConfig.allowedAuthAlgorithms.clear();
		
		try {
			Class[] wcClasses = WifiConfiguration.class.getClasses();
			Class wcEnterpriseField = null;

			for (Class wcClass : wcClasses)
				if (wcClass.getName().equals(INT_ENTERPRISEFIELD_NAME)) {
					wcEnterpriseField = wcClass;
					break;
				}
			
			boolean noEnterpriseFieldType = false;

			// noEnterpriseFieldType will be set to "true" for Android
			// Cupcake (1.5) and Donut (1.6)
			if (wcEnterpriseField == null)
				noEnterpriseFieldType = true;

			//show_in_box(ssid + " " + userName + " " + password);
			//show_in_box("noEnterpriseFieldType: " + noEnterpriseFieldType + "CLASS: " + wcEnterpriseField.getName());
			
			Field wcefAnonymousId = null, wcefCaCert = null, wcefClientCert = null, wcefEap = null, wcefIdentity = null, wcefPassword = null, wcefPhase2 = null, wcefPrivateKey = null;
			Field[] wcefFields = WifiConfiguration.class.getFields();

			// Get fields from hidden api
			for (Field wcefField : wcefFields) {
				
				if (wcefField.getName().equals(INT_ANONYMOUS_IDENTITY))
					wcefAnonymousId = wcefField;
				else if (wcefField.getName().equals(INT_CA_CERT))
					wcefCaCert = wcefField;
				else if (wcefField.getName().equals(INT_CLIENT_CERT))
					wcefClientCert = wcefField;
				else if (wcefField.getName().equals(INT_EAP))
					wcefEap = wcefField;
				else if (wcefField.getName().equals(INT_IDENTITY))
					wcefIdentity = wcefField;
				else if (wcefField.getName().equals(INT_PASSWORD))
					wcefPassword = wcefField;
				else if (wcefField.getName().equals(INT_PHASE2))
					wcefPhase2 = wcefField;
				else if (wcefField.getName().equals(INT_PRIVATE_KEY))
					wcefPrivateKey = wcefField;
			}

			Method wcefSetValue = null;
			Method wcefGetValue = null;

			if (!noEnterpriseFieldType) {
				for (Method m : wcEnterpriseField.getMethods()) {
					if (m.getName().trim().equals("setValue"))
						wcefSetValue = m;
					if (m.getName().trim().equals("value"))
						wcefGetValue = m;
				}
			}

			String retval;
			
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefEap.get(selectedConfig), ENTERPRISE_EAP);
				retval = (String) wcefGetValue.invoke(wcefEap.get(selectedConfig));
				//show_in_box("ENTERPRISE_EAP: " + retval)
			}
				
			// Phase 2
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefPhase2.get(selectedConfig), ENTERPRISE_PHASE2);
				retval = (String) wcefGetValue.invoke(wcefPhase2.get(selectedConfig));
				//show_in_box("ENTERPRISE_PHASE2: " + retval)
			}
			
			// Anonymous Identity
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefAnonymousId.get(selectedConfig), ENTERPRISE_ANON_IDENT);
				retval = (String)wcefGetValue.invoke(wcefAnonymousId.get(selectedConfig));
				//show_in_box("ENTERPRISE_ANON_IDENT: " + retval)
			}
			
			// CA certificate
	        if(!noEnterpriseFieldType) {
	        	wcefSetValue.invoke(wcefCaCert.get(selectedConfig), INT_CA_CERT);
                retval = (String)wcefGetValue.invoke(wcefCaCert.get(selectedConfig));
				//show_in_box("INT_CA_CERT: " + retval)
             }
			
			// Private key
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefPrivateKey.get(selectedConfig), ENTERPRISE_PRIV_KEY);
				retval = (String)wcefGetValue.invoke(wcefPrivateKey.get(selectedConfig));
				//show_in_box("ENTERPRISE_PRIV_KEY: " + retval)
			}
			
			// Identity (username)
			if (userName != null && userName.trim().length() > 0 && !noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefIdentity.get(selectedConfig), userName);
				retval = (String)wcefGetValue.invoke(wcefIdentity.get(selectedConfig));
				//show_in_box("userName " + retval)
			}

			// Password
			if (password != null && password.trim().length() > 0 && !noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefPassword.get(selectedConfig), password);
				retval = (String)wcefGetValue.invoke(wcefPassword.get(selectedConfig));
				//show_in_box("password " + retval)
			}
				
			// Client certificate
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefClientCert.get(selectedConfig), ENTERPRISE_CLIENT_CERT);
				retval = (String)wcefGetValue.invoke(wcefClientCert.get(selectedConfig));
				//show_in_box("ENTERPRISE_CLIENT_CERT " + retval)
			}

		} catch (Exception e) {
			e.printStackTrace();
			show_in_box("error:" + e.getMessage());
		}

		
		if (userName == null || userName.trim().length() == 0) {
			Intent wifiIntent;

			System.out.println("Starting Wifi intent");

			show_in_box("Please edit the  "+ ssid + " SSID settings and input your username(identity) and password.");
			
			wifiIntent = new Intent(WifiManager.ACTION_PICK_WIFI_NETWORK);
			wifiIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
			
			this.getApplication().startActivity(wifiIntent);
			enableWifiConfiguration(selectedConfig, false);
		}
		else {
			enableWifiConfiguration(selectedConfig, true);
		}
	}
}
