package org.packetfence.agent;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpVersion;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;

import android.content.Context;
import android.content.Intent;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.app.Activity;
import android.app.ProgressDialog;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.Toast;
import xmlwise.*;

public class MainActivity extends Activity {

	public static int EAPTYPE_TLS = 13;
	public static int EAPTYPE_LEAP = 17;
	public static int EAPTYPE_TTLS = 21;
	public static int EAPTYPE_PEAP = 25;
	public static int EAPTYPE_EAP_FAST = 43;
	public static boolean done_configuring = false;
	

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
	 * 
	 */
	public void configure(View view) throws KeyManagementException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException {

		ByteArrayOutputStream content;

		final ProgressDialog myPd_ring = ProgressDialog.show(MainActivity.this,
				"Please wait", "Configuring...", true);
		myPd_ring.setCancelable(false);

		// Show it for at least 5 seconds...
		new Thread(new Runnable() {
			@Override
			public void run() {
				// TODO Auto-generated method stub
				try {
					int t = 0;
					while (!done_configuring || t < 5000) {
						Thread.sleep(100);
						t += 100;
					}
				} catch (Exception e) {
				}
				myPd_ring.dismiss();
			}
		}).start();

		content = fetchXML();

		if (content != null) {
			parseXML(new String(content.toByteArray()));

			Button b = (Button) findViewById(R.id.button1);
			b.setEnabled(false);
		} else {
			Toast.makeText(this, "Unable to fetch configuration profile.", Toast.LENGTH_LONG).show(); 
		}
		
		done_configuring = true;
	}
	
	
	/*
	 * 
	 */
	public ByteArrayOutputStream fetchXML() throws KeyStoreException, KeyManagementException, NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException, IOException{
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);

        CustomSSLSocketFactory sf = new CustomSSLSocketFactory(trustStore);
        //sf.setHostnameVerifier(
        //       SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

        HttpParams params = new BasicHttpParams();
        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
        HttpProtocolParams.setContentCharset(params, HTTP.UTF_8);

        SchemeRegistry registry = new SchemeRegistry();
        registry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80));
        registry.register(new Scheme("https", (SocketFactory) sf, 443));

        ClientConnectionManager ccm = new ThreadSafeClientConnManager(params, registry);

        HttpClient client = new DefaultHttpClient(ccm, params);
		
        HttpGet request = new HttpGet("https://www.packetfence.org/profile.xml");
        request.setHeader("User-Agent", "Android/PacketFence Configuration Agent");
        
        ByteArrayOutputStream content = null;
        
        try {
            HttpResponse response = client.execute(request);

            // Check if server response is valid
            StatusLine status = response.getStatusLine();
            if (status.getStatusCode() != 200) {
                throw new IOException("Invalid response from server: " + status.toString());
            }

            // Pull content stream from response
            HttpEntity entity = response.getEntity();
            InputStream inputStream = entity.getContent();

            content = new ByteArrayOutputStream();

            // Read response into a buffered stream
            int readBytes = 0;
            byte[] sBuffer = new byte[512];
            while ((readBytes = inputStream.read(sBuffer)) != -1) {
                content.write(sBuffer, 0, readBytes);
            }
            
        } catch (IOException e) {
			Toast.makeText(this, "error:" + e.getMessage(), Toast.LENGTH_LONG)
			.show();
            content = null;
         }
        
        return content;
	}
	
	/*
	 * 
	 */
	public void parseXML(String xml) {
		try {
			HashMap<?, ?> hashMap = (HashMap<?, ?>) Plist.objectFromXml(xml);

			ArrayList<?> category = (ArrayList<?>) hashMap
					.get("PayloadContent");

			Object categoryObj[];
			categoryObj = category.toArray();

			for (int i = 0; i < categoryObj.length; i++) {
				HashMap<?, ?> subHashMap = (HashMap<?, ?>) categoryObj[i];

				String ssid = (String) subHashMap.get("SSID_STR");

				// We first clear any previous configuration for the SSID
				clearConfiguration(ssid);

				String encryptionType = (String) subHashMap
						.get("EncryptionType");

				//
				// Values are: WPA (PEAP, PSK), WEP
				//
				// We first handle WEP
				if (encryptionType.equalsIgnoreCase("WEP")) {
					String psk = (String) subHashMap.get("Password");
					configureWirelessConnectionWEP(ssid, psk);
				}
				// Now handle WPA (PEAP and PSK)
				else if (encryptionType.equalsIgnoreCase("WPA")) {
					HashMap<?, ?> eapClientConfigurationHashMap = (HashMap<?, ?>) subHashMap
							.get("EAPClientConfiguration");

					// Handling WPA-PEAP
					if (eapClientConfigurationHashMap != null) {
						String username = (String) eapClientConfigurationHashMap
								.get("UserName");
						String password = (String) eapClientConfigurationHashMap
								.get("UserPassword");
						ArrayList<?> eapTypes = (ArrayList<?>) eapClientConfigurationHashMap
								.get("AcceptEAPTypes");

						if (eapTypes.contains( Integer.valueOf(EAPTYPE_PEAP)) ) {
							configureWirelessConnectionWPA2PEAP(ssid, username, password);
						}


					}
					// Handling WPA-PSK
					else {
						String psk = (String) subHashMap.get("Password");
						configureWirelessConnectionWPAPSK(ssid, psk);
					}
				}

			}

		} catch (XmlParseException e) {
			Toast.makeText(this, "error:" + e.getMessage(), Toast.LENGTH_LONG)
			.show();
		}
	}
	
	/*
	 * 
	 */
	public void clearConfiguration(String ssid) {
		List<WifiConfiguration> currentConfigurations;
		WifiManager manager;

		manager = (WifiManager) getSystemService(WIFI_SERVICE);
		currentConfigurations = manager.getConfiguredNetworks();

		for (WifiConfiguration currentConfiguration : currentConfigurations) {
			if (currentConfiguration.SSID.compareToIgnoreCase(ssid) == 0) {
				manager.removeNetwork(currentConfiguration.networkId);
			}
		}

		manager.saveConfiguration();
	}
	
	/*
	 * 
	 */
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
			Toast.makeText(this, "error:" + e.getMessage(), Toast.LENGTH_LONG)
					.show();
		}
	}
	
	/*
	 * 
	 */
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
			Toast.makeText(this, "error:" + e.getMessage(), Toast.LENGTH_LONG)
					.show();
		}
	}
	
	/*
	 * 
	 */
	public void configureWirelessConnectionWPA2PEAP(String ssid,
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

			//Toast.makeText(this, ssid + " " + userName + " " + password, Toast.LENGTH_LONG).show();
			//Toast.makeText(this, "noEnterpriseFieldType: " + noEnterpriseFieldType + "CLASS: " + wcEnterpriseField.getName(), Toast.LENGTH_LONG).show(); 
			
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
				retval = (String) wcefGetValue.invoke(wcefEap.get(selectedConfig), null);
				//Toast.makeText(this, "ENTERPRISE_EAP: " + retval, Toast.LENGTH_LONG).show(); 
			}
				
			// Phase 2
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefPhase2.get(selectedConfig), ENTERPRISE_PHASE2);
				retval = (String) wcefGetValue.invoke(wcefPhase2.get(selectedConfig), null);
				//Toast.makeText(this, "ENTERPRISE_PHASE2: " + retval, Toast.LENGTH_LONG).show(); 
			}
			
			// Anonymous Identity
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefAnonymousId.get(selectedConfig), ENTERPRISE_ANON_IDENT);
				retval = (String)wcefGetValue.invoke(wcefAnonymousId.get(selectedConfig), null);
				//Toast.makeText(this, "ENTERPRISE_ANON_IDENT: " + retval, Toast.LENGTH_LONG).show(); 
			}
			
			// CA certificate
	        if(!noEnterpriseFieldType) {
                 wcefSetValue.invoke(wcefCaCert.get(selectedConfig), INT_CA_CERT);
                 retval = (String)wcefGetValue.invoke(wcefCaCert.get(selectedConfig), null);
                 //Toast.makeText(this, "INT_CA_CERT: " + retval, Toast.LENGTH_LONG).show(); 
             }
			
			// Private key
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefPrivateKey.get(selectedConfig), ENTERPRISE_PRIV_KEY);
				retval = (String)wcefGetValue.invoke(wcefPrivateKey.get(selectedConfig), null);
				//Toast.makeText(this, "ENTERPRISE_PRIV_KEY: " + retval, Toast.LENGTH_LONG).show(); 
			}
			
			// Identity (username)
			if (userName != null && userName.trim().length() > 0 && !noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefIdentity.get(selectedConfig), userName);
				retval = (String)wcefGetValue.invoke(wcefIdentity.get(selectedConfig), null);
				//Toast.makeText(this, "userName " + retval, Toast.LENGTH_LONG).show(); 
			}

			// Password
			if (password != null && password.trim().length() > 0 && !noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefPassword.get(selectedConfig), password);
				retval = (String)wcefGetValue.invoke(wcefPassword.get(selectedConfig), null);
				//Toast.makeText(this, "password " + retval, Toast.LENGTH_LONG).show(); 
			}
				
			// Client certificate
			if (!noEnterpriseFieldType) {
				wcefSetValue.invoke(wcefClientCert.get(selectedConfig), ENTERPRISE_CLIENT_CERT);
				retval = (String)wcefGetValue.invoke(wcefClientCert.get(selectedConfig), null);
				//Toast.makeText(this, "ENTERPRISE_CLIENT_CERT " + retval, Toast.LENGTH_LONG).show();
			}
			// try{
			// Field wcAdhoc = WifiConfiguration.class.getField("adhocSSID");
			// Field wcAdhocFreq =
			// WifiConfiguration.class.getField("frequency");
			//
			// wcAdhoc.setBoolean(selectedConfig, false);
			// int freq = 2462;
			// wcAdhocFreq.setInt(selectedConfig, freq);
			// } catch (Exception e)
			// {
			// e.printStackTrace();
			// }

		} catch (Exception e) {
			Toast.makeText(this, "error:" + e.getMessage(), Toast.LENGTH_LONG)
			.show();
			e.printStackTrace();
		}

		
		if (userName == null || userName.trim().length() == 0) {
			Intent wifiIntent;
			
			Toast.makeText(this, "Please select the  "+ ssid + " SSID to complete the configuration.", Toast.LENGTH_LONG)
			.show();
			
			wifiIntent = new Intent(WifiManager.ACTION_PICK_WIFI_NETWORK);
			wifiIntent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
			
			this.getApplication().startActivity(wifiIntent);
			enableWifiConfiguration(selectedConfig, false);
		}
		else {
			enableWifiConfiguration(selectedConfig, true);
		}
	}
	
	/*
	 * 
	 */
	public void enableWifiConfiguration(WifiConfiguration config, boolean connect) {
		WifiManager wifi = (WifiManager) getSystemService(WIFI_SERVICE);

		int ret;
		
		ret = wifi.addNetwork(config);
		
		if (connect) {
	    	wifi.enableNetwork(ret, false);   
		}
		
	    wifi.saveConfiguration();
	    
	    if (connect) {
	    	wifi.enableNetwork(ret, true);
	    }
	}
	
	/*
	 * 
	 */
	public void quit(View view) {
		System.exit(0);
	}

}
