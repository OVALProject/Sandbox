//
//
//****************************************************************************************//
// Copyright (c) 2002-2013, The MITRE Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice, this list
//       of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright notice, this 
//       list of conditions and the following disclaimer in the documentation and/or other
//       materials provided with the distribution.
//     * Neither the name of The MITRE Corporation nor the names of its contributors may be
//       used to endorse or promote products derived from this software without specific 
//       prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY 
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
// SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
// EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//****************************************************************************************//


package org.mitre.oval.androidsc;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.BitSet;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.xmlbeans.XmlCursor;
import org.mitre.oval.xmlSchema.ovalCommon5.GeneratorType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.CollectedObjectsType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemBinaryType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemBoolType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemIntType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemStringType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemVersionType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.FlagEnumeration;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.InterfaceType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.InterfacesType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.ItemType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.ObjectType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.OvalSystemCharacteristicsDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.ReferenceType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.SystemDataType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.SystemInfoType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.OvalSystemCharacteristicsDocument.OvalSystemCharacteristics;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.AppManagerItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.AppManagerItemDocument.AppManagerItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.BluetoothItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.BluetoothItemDocument.BluetoothItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.CameraItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.CameraItemDocument.CameraItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.CertificateItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.CertificateItemDocument.CertificateItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.DeviceAccessItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.DeviceAccessItemDocument.DeviceAccessItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.DeviceSettingsItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.DeviceSettingsItemDocument.DeviceSettingsItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EncryptionItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EncryptionItemDocument.EncryptionItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemExternalStorageType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemNetworkType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemPasswordQualityType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemWifiAuthAlgorithmType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemWifiCurrentStatusType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemWifiGroupCipherType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemWifiKeyMgmtType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemWifiPairwiseCipherType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.EntityItemWifiProtocolType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.ExternalStorageItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.ExternalStorageItemDocument.ExternalStorageItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.LocationServiceItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.LocationServiceItemDocument.LocationServiceItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.NetworkItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.NetworkItemDocument.NetworkItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.PasswordItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.PasswordItemDocument.PasswordItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.SystemDetailsItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.SystemDetailsItemDocument.SystemDetailsItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.TelephonyItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.TelephonyItemDocument.TelephonyItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.WifiItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.WifiItemDocument.WifiItem;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.WifiSecurityItemDocument;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.WifiSecurityItemDocument.WifiSecurityItem;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import android.app.admin.DevicePolicyManager;
import android.bluetooth.BluetoothAdapter;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.location.LocationManager;
import android.net.ConnectivityManager;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiManager;
import android.nfc.NfcAdapter;
import android.os.Build;
import android.os.Environment;
import android.os.storage.StorageManager;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.Log;

public class GenerateAndroidSC {

	// from http://rgagnon.com/javadetails/java-0596.html
	static final String HEXES = "0123456789ABCDEF";

	public static String getHex(byte[] raw, String separator) {
		if (raw == null) {
			return null;
		}
		final StringBuilder hex = new StringBuilder(2 * raw.length);
		for (final byte b : raw) {
			hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(
					HEXES.charAt((b & 0x0F)));
			if(separator != null)
				hex.append(separator);
		}
		String out = hex.toString();
		return out.toString().substring(0, out.length() - 1);

	}

	static void generate(Context c, String inputFile, String outputFile) {
		int current_item_ref = 1;

		OvalSystemCharacteristicsDocument oscDoc = null;
		oscDoc = OvalSystemCharacteristicsDocument.Factory.newInstance();

		OvalSystemCharacteristics osc = oscDoc
				.addNewOvalSystemCharacteristics();
		GeneratorType gt = osc.addNewGenerator();
		SystemInfoType si = osc.addNewSystemInfo();
		CollectedObjectsType co = osc.addNewCollectedObjects();
		SystemDataType sd = osc.addNewSystemData();

		gt.setProductName("cpe:/a:mitre:androidsc:0.2");
		gt.setProductVersion("0.2");
		gt.setSchemaVersion("5.10.1"); // can we gather this from somewhere
		gt.setTimestamp(Calendar.getInstance());

		si.setOsName("Android");
		si.setOsVersion(Build.VERSION.RELEASE);
		si.setArchitecture(Build.CPU_ABI);

		si.setPrimaryHostName(Settings.Secure.getString(c.getContentResolver(),
				Settings.Secure.ANDROID_ID)); // is this an appropriate value
												// for hostname
		// ANDROID_ID is a random value generated when the OS boots for the first time
		// (it is refreshed any time a factory reset is done)
		
		// Ensure that we have at least one interface with an interface name,
		// IP, and MAC address
		// if so, include all applicable interfaces.
		// Otherwise don't include any interfaces at all.
		//
		Enumeration<NetworkInterface> ifs = null;
		try {
			ifs = NetworkInterface.getNetworkInterfaces();
			InterfacesType ist = si.addNewInterfaces();

			if (ifs != null) {
				
				while (ifs.hasMoreElements()) {
					NetworkInterface iface = ifs.nextElement();

					// Make sure the interface has an IP and MAC address before
					// inserting
					Enumeration<InetAddress> ips = iface.getInetAddresses();
					String ipString = null;
					String macAddressString = null;

					// Interfaces sometimes have more than one IP address (for example both IPv4 and IPv6 addresses). 
					// This adds whatever the last IP address is that is listed
					while (ips.hasMoreElements()) {
						InetAddress ip = ips.nextElement();
						byte[] ipAddress = ip.getAddress();
						ipString = ip.getHostAddress();
					}

					byte[] macAddress = iface.getHardwareAddress();
					if (macAddress != null) {
						macAddressString = getHex(macAddress, "-");
						
					}

					if ((ipString != null) && (macAddressString != null)) {
						InterfaceType it = ist.addNewInterface();
						it.setInterfaceName(iface.getDisplayName());
						it.setIpAddress(ipString);
						it.setMacAddress(macAddressString);
					}
				}
			} else {
				Log.d("AndroidSC", "Ifs was null");
			}
		} catch (SocketException ex) {
			// error handling appropriate for your application
			Log.d("AndroidSC", ex.toString());
		}

		Log.d("AndroidSC",
				"External storage: "
						+ Environment.getExternalStorageDirectory());
		File ovalDefFile;
		if ((inputFile != null) && (inputFile.length() > 0)) {
			ovalDefFile = new File(Environment.getExternalStorageDirectory(),
					inputFile);
		} else
			return;
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory
					.newInstance();
			DocumentBuilder builder = factory.newDocumentBuilder();
			Document dom = builder.parse(ovalDefFile);
			org.w3c.dom.Element root = dom.getDocumentElement();
			NodeList objects = root.getElementsByTagName("objects");
			// Log.d("AndroidSC", "Objects count " + objects.getLength());
			if (objects.getLength() > 0) {
				org.w3c.dom.Node objects1 = objects.item(0);
				NodeList innerobjects = objects1.getChildNodes();
				// use tag name and ID to call probes
				for (int i = 0; i < innerobjects.getLength(); i++) {
					org.w3c.dom.Node innerobject = innerobjects.item(i);

					String objectName = innerobject.getNodeName();
					// Log.d("AndroidSC", "Object name " + objectName);
					if (objectName != null) {
						NamedNodeMap objectAttrs = innerobject.getAttributes();
						if (objectAttrs != null) {
							Node idNode = objectAttrs.getNamedItem("id");
							if (idNode == null) {
							//	Log.d("AndroidSC", "id null");
							} else {
								String id = idNode.getNodeValue();
								if (objectName.equals("system_details_object")) {

									generateSystemDetailsItem(co, sd, id,
											current_item_ref);
									current_item_ref++;
								} else if (objectName.equals("password_object")) {
									generatePasswordItem(co, sd, id,
											current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("camera_object")) {
										generateCameraItem(co, sd, id,
												current_item_ref, c);
										current_item_ref++;
								} else if (objectName
										.equals("encryption_object")) {
									generateEncryptionItem(co, sd, id,
											current_item_ref, c);
									current_item_ref++;
								} else if (objectName
										.equals("device_access_object")) {
									generateDeviceAccessItem(co, sd, id,
											current_item_ref, c);
									current_item_ref++;
								} else if (objectName
										.equals("app_manager_object")) {
									// Temporarily for now: Match all apps
									current_item_ref = generateAppManagerItems(
											co, sd, id, current_item_ref, c);
								} else if (objectName
										.equals("wifi_security_object")) {
									current_item_ref = generateWifiSecurityItems(
											co, sd, id, current_item_ref, c);
								} else if (objectName.equals("bluetooth_object")) {
									generateBluetoothItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("wifi_object")) {
									generateWifiItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("location_service_object")) {
									generateLocationServiceItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("network_object")) {
									generateNetworkItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("device_settings_object")) {
									generateDeviceSettingsItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("certificate_object")) {
									generateCertificateItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								} else if (objectName.equals("external_storage_object")) {
									current_item_ref = generateExternalStorageItem(co, sd, id, current_item_ref, c);
								} else if (objectName.equals("telephony_object")) {
									generateTelephonyItem(co, sd, id, current_item_ref, c);
									current_item_ref++;
								}
							}
						} else {
							Log.d("AndroidSC", "objectAttrs null");
						}
					}
				}
			}
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		XmlCursor cursor = oscDoc.newCursor();
		if (cursor.toFirstChild()) {
			cursor.setAttributeText(
					new QName("http://www.w3.org/2001/XMLSchema-instance",
							"schemaLocation"),
					"http://oval.mitre.org/XMLSchema/oval-system-characteristics-5 oval-system-characteristics-schema.xsd "
							+ "http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd "
							+ "http://oval.mitre.org/XMLSchema/oval-system-characteristics-5#android x-android-system-characteristics.xsd");
		}

		Log.d("AndroidSC", "SchemaLocation set");

		// File extDir = getExternalFilesDir(null);

		// if(extDir != null) {
		try {

			File newFile;
			if ((outputFile != null) && (outputFile.length() > 0)) {
				newFile = new File(Environment.getExternalStorageDirectory(),
						outputFile);
			} else
				return;
			OutputStream out = new FileOutputStream(newFile);

			out.write(oscDoc.toString().getBytes());
			out.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void generateCameraItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve camera_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();

		CameraItem ci = (CameraItem) it2.substitute(
				CameraItemDocument.type.getDocumentElementName(),
				CameraItem.type);
		ci.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above
		DevicePolicyManager dpm = (DevicePolicyManager) c
			.getSystemService(Context.DEVICE_POLICY_SERVICE);
		if (dpm == null)
			return;
		if(android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
			Gatherer g = new ICSGatherer();
			g.camera(ci, dpm);
		}
	}
	
	public static void generateSystemDetailsItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref) {
		ObjectType ot = co.addNewObject();

		ot.setComment("Retrieve system_details_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();
		SystemDetailsItem sdi = (SystemDetailsItem) it2.substitute(
				SystemDetailsItemDocument.type.getDocumentElementName(),
				SystemDetailsItem.type);
		sdi.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above

		Log.d("AndroidSC", "Setting stuff");

		EntityItemStringType ei1 = EntityItemStringType.Factory.newInstance();
		ei1.setStringValue(Build.FINGERPRINT);
		sdi.setBuildFingerprint(ei1);

		if( (Build.CPU_ABI != null) && !(Build.CPU_ABI.equals("")) )
		{
			EntityItemStringType cpuAbi = sdi.addNewCpuAbi();
			cpuAbi.setStringValue(Build.CPU_ABI);
		}
		
		if( (Build.CPU_ABI2 != null) && !(Build.CPU_ABI2.equals("")) )
		{
			EntityItemStringType cpuAbi = sdi.addNewCpuAbi();
			cpuAbi.setStringValue(Build.CPU_ABI2);
		}

		EntityItemStringType ei3 = EntityItemStringType.Factory.newInstance();
		ei3.setStringValue(Build.HARDWARE);
		sdi.setHardware(ei3);

		EntityItemStringType ei4 = EntityItemStringType.Factory.newInstance();
		ei4.setStringValue(Build.MANUFACTURER);
		sdi.setManufacturer(ei4);

		EntityItemStringType ei5 = EntityItemStringType.Factory.newInstance();
		ei5.setStringValue(Build.MODEL);
		sdi.setModel(ei5);

		EntityItemStringType ei6 = EntityItemStringType.Factory.newInstance();
		ei6.setStringValue(Build.VERSION.INCREMENTAL);
		sdi.setOsVersionBuildNumber(ei6); // is this the correct value to use?

		EntityItemStringType ei7 = EntityItemStringType.Factory.newInstance();
		ei7.setStringValue(Build.VERSION.RELEASE);
		sdi.setOsVersionReleaseName(ei7);

		EntityItemIntType ei8 = EntityItemIntType.Factory.newInstance();
		ei8.setStringValue(String.valueOf(Build.VERSION.SDK_INT));
		ei8.setDatatype("int");
		sdi.setOsVersionSdkNumber(ei8);

		EntityItemStringType ei9 = EntityItemStringType.Factory.newInstance();
		ei9.setStringValue(Build.PRODUCT);
		sdi.setProduct(ei9);
		
		EntityItemStringType ei10 = EntityItemStringType.Factory.newInstance();
		ei10.setStringValue(Build.VERSION.CODENAME);
		sdi.setOsVersionCodeName(ei10);
		
		int sdk = Build.VERSION.SDK_INT;
		if(sdk >= 18) {
			Gatherer g = new JellyBeanMR2Gatherer();
			g.systemDetails(sdi);
		}
		
		
	}

	public static void generatePasswordItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve password_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();

		PasswordItem pi = (PasswordItem) it2.substitute(
				PasswordItemDocument.type.getDocumentElementName(),
				PasswordItem.type);
		pi.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above
		DevicePolicyManager dpm = (DevicePolicyManager) c
				.getSystemService(Context.DEVICE_POLICY_SERVICE);
		if (dpm == null)
			return;

		// Ref:
		// http://developer.android.com/reference/android/app/admin/DevicePolicyManager.html

		// Availability depends on Android SDK Version
		// Probably need to separately handle each version.
		// http://android-developers.blogspot.com/2010/07/how-to-have-your-cupcake-and-eat-it-too.html

		// API Level 8 (Android 2.2)
		EntityItemIntType ei1 = EntityItemIntType.Factory.newInstance();
		ei1.setStringValue(Integer.valueOf(
				dpm.getMaximumFailedPasswordsForWipe(null)).toString());
		ei1.setDatatype("int");
		pi.setMaxNumFailedUserAuth(ei1);


		// API Level 8 (Android 2.2 and up)
		EntityItemPasswordQualityType quality = EntityItemPasswordQualityType.Factory.newInstance();
		int qualityInt = dpm.getPasswordQuality(null);
		if(qualityInt == DevicePolicyManager.PASSWORD_QUALITY_ALPHABETIC) {
			quality.setStringValue("PASSWORD_QUALITY_ALPHABETIC");
			pi.setPasswordQuality(quality);
		} else if (qualityInt == DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC) {
			quality.setStringValue("PASSWORD_QUALITY_ALPHANUMERIC");
			pi.setPasswordQuality(quality);
		} else if (qualityInt == DevicePolicyManager.PASSWORD_QUALITY_BIOMETRIC_WEAK) {
			quality.setStringValue("PASSWORD_QUALITY_BIOMETRIC_WEAK");
			pi.setPasswordQuality(quality);
		} else if (qualityInt == DevicePolicyManager.PASSWORD_QUALITY_COMPLEX) {
			quality.setStringValue("PASSWORD_QUALITY_COMPLEX");
			pi.setPasswordQuality(quality);
		} else if (qualityInt == DevicePolicyManager.PASSWORD_QUALITY_NUMERIC) {
			quality.setStringValue("PASSWORD_QUALITY_NUMERIC");
			pi.setPasswordQuality(quality);
		} else if (qualityInt == DevicePolicyManager.PASSWORD_QUALITY_SOMETHING) {
			quality.setStringValue("PASSWORD_QUALITY_SOMETHING");
			pi.setPasswordQuality(quality);
		} else if (qualityInt == DevicePolicyManager.PASSWORD_QUALITY_UNSPECIFIED) {
			quality.setStringValue("PASSWORD_QUALITY_UNSPECIFIED");
			pi.setPasswordQuality(quality);
		}
		
		
		// Fix: Need to specify quality:
		// sdi.setPasswordMaxLength(dpm.getPasswordMaximumLength());
		// May drop max length from schema
		
		// API Level 8
		EntityItemIntType ei4 = EntityItemIntType.Factory.newInstance();
		ei4.setStringValue(Integer.valueOf(dpm.getPasswordMinimumLength(null))
				.toString());
		ei4.setDatatype("int");
		pi.setPasswordMinLength(ei4);

		EntityItemBoolType ei12 = EntityItemBoolType.Factory.newInstance();
		int textShowPassword = Settings.System.getInt(c.getContentResolver(),
				Settings.System.TEXT_SHOW_PASSWORD, 1); // API Level 1
		if(textShowPassword == 1)
			ei12.setStringValue("true");
		else
			ei12.setStringValue("false");
		ei12.setDatatype("boolean");
		pi.setPasswordVisible(ei12); // Whether or not last entered
										// character
										// is briefly displayed
		// or if it is immediately masked with a *
		// Set in Settings menu on device

		
		// Crashes if this app is not enabled as an admin.
		//EntityItemBoolType ei13 = EntityItemBoolType.Factory.newInstance();
		//ei13.setStringValue(String.valueOf(dpm.isActivePasswordSufficient()));
		//pi.setActivePasswordSufficient(ei13); // API Level 8
		
		// Crashes if this app is not enabled as an admin.
		//EntityItemIntType ei14 = EntityItemIntType.Factory.newInstance();
		//ei14.setStringValue(String.valueOf(dpm.getCurrentFailedPasswordAttempts()));
		//pi.setCurrentFailedPasswordAttempts(ei14); // API Level 8
		
		int sdk = Build.VERSION.SDK_INT;
		if(sdk >= 11) {
			// Gather stuff only available in API Level 11 or higher
			Gatherer g = new HoneycombGatherer();
			g.password(pi, dpm);
		}
	}

	public static void generateBluetoothItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve bluetooth_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();

		BluetoothItem bi = (BluetoothItem) it2.substitute(
				BluetoothItemDocument.type.getDocumentElementName(),
				BluetoothItem.type);
		bi.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
												// value above
		// Retrieve from Settings -- other option is to get from
		// BluetoothAdapter,
		// but that requires BLUETOOTH permission.

		int bluetoothOn = Settings.System.getInt(c.getContentResolver(),
				Settings.System.BLUETOOTH_ON, 0);

		//int bluetoothDiscover = Settings.System.getInt(c.getContentResolver(),
			//	Settings.System.BLUETOOTH_DISCOVERABILITY, 0);

		BluetoothAdapter bAdapter = BluetoothAdapter.getDefaultAdapter();
		int scanMode = bAdapter.getScanMode();
		
		String bluetoothTimeout = Settings.System.getString(c.getContentResolver(),
				Settings.System.BLUETOOTH_DISCOVERABILITY_TIMEOUT);
	
		
		// Android doesn't appear to populate BLUETOOTH_DISCOVERABILITY and BLUETOOTH_DISCOVERABILITY_TIMEOUT
		//
		// Reported to Google here: https://code.google.com/p/android/issues/detail?id=56589
		//
		// Bluetooth discoverability can be obtained using BluetoothAdapter.getScanMode(),
		// but the discoverability timeout method, BluetoothAdapter.getDiscoverableTimeout() is not publicly exposed
		// through the Android SDK for some reason.
		EntityItemBoolType ei1 = EntityItemBoolType.Factory.newInstance();

		if (bluetoothOn > 0) {
			ei1.setStringValue("true");
		} else {
			ei1.setStringValue("false");
		}
		ei1.setDatatype("boolean");
		bi.setCurrentStatus(ei1);

		EntityItemBoolType ei2 = EntityItemBoolType.Factory.newInstance();
		if (scanMode == BluetoothAdapter.SCAN_MODE_CONNECTABLE_DISCOVERABLE) {
			ei2.setStringValue("true");
		} else {
			ei2.setStringValue("false");
		}
		ei2.setDatatype("boolean");
		bi.setDiscoverable(ei2);
				
		if(bluetoothTimeout != null) {
			EntityItemIntType ei3 = EntityItemIntType.Factory.newInstance();
			ei3.setStringValue(bluetoothTimeout);
			ei3.setDatatype("int");
			bi.setDiscoverabilityTimeout(ei3);
		} else { // Attempt to obtain through reflection on BluetoothAdapter
			try {
				Method[] baMethods = bAdapter.getClass().getDeclaredMethods();
				for(Method method : baMethods) {
					if(method.getName().equals("getDiscoverableTimeout")) {
						Integer dTimeout = (Integer) method.invoke(bAdapter);
						if(dTimeout != null && dTimeout.intValue() >= 0) {
							EntityItemIntType ei3 = EntityItemIntType.Factory.newInstance();
							ei3.setStringValue(dTimeout.toString());
							ei3.setDatatype("int");
							bi.setDiscoverabilityTimeout(ei3);
						}
					}
				}
			} catch (Exception e) {}
		}
	}



	public static void generateEncryptionItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve encryption_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();

		EncryptionItem ei = (EncryptionItem) it2.substitute(
				EncryptionItemDocument.type.getDocumentElementName(),
				EncryptionItem.type);
		ei.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above
		DevicePolicyManager dpm = (DevicePolicyManager) c
				.getSystemService(Context.DEVICE_POLICY_SERVICE);
		if (dpm == null)
			return;

		int sdk = Build.VERSION.SDK_INT;
		if(sdk >= 11) {
			Gatherer g = new HoneycombGatherer();
			g.encryption(ei, dpm);
		}
	}

	public static void generateDeviceAccessItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		// Doesn't do anything yet - not sure how to gather timeout value

		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve device_access_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();

		DeviceAccessItem dai = (DeviceAccessItem) it2.substitute(
				DeviceAccessItemDocument.type.getDocumentElementName(),
				DeviceAccessItem.type);
		dai.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above
		
		DevicePolicyManager dpm = (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE); 
		if (dpm == null)
			return;
		 
		EntityItemIntType ei1 = EntityItemIntType.Factory.newInstance();
		ei1.setStringValue(String.valueOf(dpm.getMaximumTimeToLock(null)));
		ei1.setDatatype("int");
		dai.setScreenLockTimeout(ei1);
		
		int sdk = Build.VERSION.SDK_INT;
		if(sdk >= 17) {
			Gatherer g = new JellyBeanMR1Gatherer();
			g.device_access(dai, dpm);
		}

	}

	// LocationServiceItem
	public static void generateLocationServiceItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		// May require location permission - not sure yet
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve location_service_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));
		ItemType it2 = sd.addNewItem();

		LocationServiceItem lsi = (LocationServiceItem) it2.substitute(
				LocationServiceItemDocument.type.getDocumentElementName(),
				LocationServiceItem.type);
		lsi.setId(BigInteger.valueOf(item_ref));

		LocationManager ls = (LocationManager) c
				.getSystemService(Context.LOCATION_SERVICE);
		if (ls == null)
			return;
		boolean gpsEnabled = ls.isProviderEnabled(LocationManager.GPS_PROVIDER);
		EntityItemBoolType ei1 = EntityItemBoolType.Factory.newInstance();

		if (gpsEnabled) {
			ei1.setStringValue("true");
		} else {
			ei1.setStringValue("false");
		}
		ei1.setDatatype("boolean");
		lsi.setGpsEnabled(ei1);

		boolean networkEnabled = ls
				.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
		EntityItemBoolType ei2 = EntityItemBoolType.Factory.newInstance();
		if (networkEnabled) {
			ei2.setStringValue("true");
		} else {
			ei2.setStringValue("false");
		}
		ei2.setDatatype("boolean");
		lsi.setNetworkEnabled(ei2);
	}

	public static void generateNetworkItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve network_preference_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix
	
		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));
		ItemType it2 = sd.addNewItem();
	
		NetworkItem ni = (NetworkItem) it2.substitute(
				NetworkItemDocument.type.getDocumentElementName(), NetworkItem.type);
		ni.setId(BigInteger.valueOf(item_ref));
		
		int airplaneMode = Settings.System.getInt(c.getContentResolver(),
				Settings.System.AIRPLANE_MODE_ON, 0);
		EntityItemBoolType airplaneBool = EntityItemBoolType.Factory.newInstance();
		if(airplaneMode == 1)
			airplaneBool.setStringValue("true");
		else
			airplaneBool.setStringValue("false");
		airplaneBool.setDatatype("boolean");
		ni.setAirplaneMode(airplaneBool);
		
		EntityItemBoolType nfcBool = EntityItemBoolType.Factory.newInstance();
		NfcAdapter nfc = NfcAdapter.getDefaultAdapter(c);
		if(nfc != null) {
			if(nfc.isEnabled())
				nfcBool.setStringValue("true");
			else
				nfcBool.setStringValue("false");
		} else {
			nfcBool.setStringValue("false");
		}
		nfcBool.setDatatype("boolean");
		ni.setNfcEnabled(nfcBool);
		
		EntityItemBoolType tetherBool = EntityItemBoolType.Factory.newInstance();
		EntityItemBoolType tetherActiveBool = EntityItemBoolType.Factory.newInstance();
		
		ConnectivityManager cm = (ConnectivityManager) c.getSystemService(Context.CONNECTIVITY_SERVICE);
		
		try {
			Method[] cmMethods = cm.getClass().getDeclaredMethods();
			for(Method method : cmMethods) {
				if(method.getName().equals("isTetheringSupported")) {
					boolean isTetherSupt = (Boolean) method.invoke(cm);
					if(isTetherSupt == true) {
						tetherBool.setStringValue("true");
						tetherBool.setDatatype("boolean");
						ni.setTetherSupported(tetherBool);
					} if(isTetherSupt == false) {
						tetherBool.setStringValue("false");
						tetherBool.setDatatype("boolean");
						ni.setTetherSupported(tetherBool);
					}
				}
				if(method.getName().equals("getTetheredIfaces")) {
					String[] tethered = (String[]) method.invoke(cm);
					if(tethered != null && tethered.length == 0) {
						tetherActiveBool.setStringValue("false");
						tetherActiveBool.setDatatype("boolean");
						ni.setTetherActive(tetherActiveBool);
					} else if (tethered != null && tethered.length > 0) {
						tetherActiveBool.setStringValue("true");
						tetherActiveBool.setDatatype("boolean");
						ni.setTetherActive(tetherActiveBool);
					}
				}
			}
			
		} catch (Exception e) {}
		
		
		
	}
	
	public static int generateExternalStorageItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve external_storage_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		StorageManager sm = (StorageManager) c.getSystemService(Context.STORAGE_SERVICE);
		
		// need to call getVolumeList on sm, which returns StorageVolume[], but
		// we don't have either available to us..
		try {
			
			Method[] smMethods = sm.getClass().getDeclaredMethods();
			Method getVolumeState = null;
			
			for(Method method3: smMethods)
				if(method3.getName().equals("getVolumeState")) {
					getVolumeState = method3;
				}
			
			for(Method method: smMethods)
				if(method.getName().equals("getVolumeList")) {
					Object[] storageVolumes = (Object[]) method.invoke(sm);
				
					for(Object storageVolume : storageVolumes) {
						ReferenceType rt = ot.addNewReference();
						rt.setItemRef(BigInteger.valueOf(item_ref));
						ItemType it2 = sd.addNewItem();
						ExternalStorageItem esi = (ExternalStorageItem) it2.substitute(
								ExternalStorageItemDocument.type.getDocumentElementName(), ExternalStorageItem.type);
						esi.setId(BigInteger.valueOf(item_ref));
						item_ref++;
						
						Method[] svMethods = storageVolume.getClass().getDeclaredMethods();
						for(Method method2: svMethods) {
							if(method2.getName().equals("isRemovable")) {
								boolean removable = (Boolean) method2.invoke(storageVolume);
								if(removable == true) {
									EntityItemBoolType esi2 = EntityItemBoolType.Factory.newInstance();
									esi2.setStringValue("true");
									esi2.setDatatype("boolean");
									esi.setExternalStorageRemovable(esi2);
								} else if (removable == false) {
									EntityItemBoolType esi2 = EntityItemBoolType.Factory.newInstance();
									esi2.setStringValue("false");
									esi2.setDatatype("boolean");
									esi.setExternalStorageRemovable(esi2);
								}
							}
							if(method2.getName().equals("getPath")) {
								String path = (String) method2.invoke(storageVolume);
								EntityItemStringType path2 = EntityItemStringType.Factory.newInstance();
								path2.setStringValue(path);
								esi.setPath(path2);
								
								if(getVolumeState != null) {
									EntityItemExternalStorageType esi1 = EntityItemExternalStorageType.Factory.newInstance();
									String storageState = (String) getVolumeState.invoke(sm, path);
									if(storageState.equals(Environment.MEDIA_BAD_REMOVAL)) {
										esi1.setStringValue("MEDIA_BAD_REMOVAL");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_CHECKING)) {
										esi1.setStringValue("MEDIA_CHECKING");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_MOUNTED)) {
										esi1.setStringValue("MEDIA_MOUNTED");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_MOUNTED_READ_ONLY)) {
										esi1.setStringValue("MEDIA_MOUNTED_READ_ONLY");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_NOFS)) {
										esi1.setStringValue("MEDIA_NOFS");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_REMOVED)) {
										esi1.setStringValue("MEDIA_REMOVED");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_SHARED)) {
										esi1.setStringValue("MEDIA_SHARED");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_UNMOUNTABLE)) {
										esi1.setStringValue("MEDIA_UNMOUNTABLE");
										esi.setExternalStorageState(esi1);
									}
									else if(storageState.equals(Environment.MEDIA_UNMOUNTED)) {
										esi1.setStringValue("MEDIA_UNMOUNTED");
										esi.setExternalStorageState(esi1);
									}
									
								}
							}
						}
					}
					
				}
		} catch (Exception e) {
			Log.d("GenerateAndroidSC", "EXTERNAL STORAGE " + e.getMessage());
		}
		return item_ref;
		
	}
	
	
	public static void generateWifiItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {

		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve wifi_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));
		ItemType it2 = sd.addNewItem();

		WifiItem wi = (WifiItem) it2.substitute(
				WifiItemDocument.type.getDocumentElementName(), WifiItem.type);
		wi.setId(BigInteger.valueOf(item_ref));

		WifiManager wm = (WifiManager) c.getSystemService(Context.WIFI_SERVICE);
		if (wm == null)
			return;

		EntityItemBoolType ei2 = EntityItemBoolType.Factory.newInstance();
		if(wm.isWifiEnabled())
			ei2.setStringValue("true");
		else
			ei2.setStringValue("false");
		ei2.setDatatype("boolean");
		wi.setWifiStatus(ei2);

		int wifiNotification = Settings.Secure.getInt(c.getContentResolver(),
				Settings.Secure.WIFI_NETWORKS_AVAILABLE_NOTIFICATION_ON, 0);
		EntityItemBoolType ei3 = EntityItemBoolType.Factory.newInstance();
		if(wifiNotification == 1)
			ei3.setStringValue("true");
		else
			ei3.setStringValue("false");
		ei3.setDatatype("boolean");
		wi.setNetworkAvailabilityNotification(ei3);
	}

	// WifiSecurityItem
	public static int generateWifiSecurityItems(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve wifi_security_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		WifiManager wm = (WifiManager) c.getSystemService(Context.WIFI_SERVICE);
		if (wm == null)
			return item_ref;

		List<WifiConfiguration> configurations = wm.getConfiguredNetworks();
		if(configurations == null)
			return item_ref;
		
		for (WifiConfiguration wc : configurations) {
			ReferenceType rt = ot.addNewReference();
			rt.setItemRef(BigInteger.valueOf(item_ref));
		
			ItemType it2 = sd.addNewItem();
			WifiSecurityItem wsi = (WifiSecurityItem) it2.substitute(
					WifiSecurityItemDocument.type.getDocumentElementName(),
					WifiSecurityItem.type);
			wsi.setId(BigInteger.valueOf(item_ref)); // Needs to match
														// setItemRef
														// value above
			item_ref++;
			
			if(wc.BSSID != null) {
				EntityItemStringType ei1 = EntityItemStringType.Factory
					.newInstance();
				ei1.setStringValue(wc.BSSID);
				wsi.setBssid(ei1);
			}
			
			EntityItemStringType ei2 = EntityItemStringType.Factory
					.newInstance();
			ei2.setStringValue(wc.SSID);
			wsi.setSsid(ei2);

			EntityItemStringType ei3 = EntityItemStringType.Factory
					.newInstance();
			BitSet wifiauth = wc.allowedAuthAlgorithms;
			
			if(wifiauth.get(WifiConfiguration.AuthAlgorithm.OPEN))
			{
				EntityItemWifiAuthAlgorithmType authalg = wsi.addNewAuthAlgorithms();
				authalg.setStringValue("OPEN");
			}
			
			if(wifiauth.get(WifiConfiguration.AuthAlgorithm.SHARED))
			{
				EntityItemWifiAuthAlgorithmType authalg = wsi.addNewAuthAlgorithms();
				authalg.setStringValue("SHARED");
			}
			
			if(wifiauth.get(WifiConfiguration.AuthAlgorithm.LEAP))
			{
				EntityItemWifiAuthAlgorithmType authalg = wsi.addNewAuthAlgorithms();
				authalg.setStringValue("LEAP");
			}

			BitSet groupciphers = wc.allowedGroupCiphers;
			if(groupciphers.get(WifiConfiguration.GroupCipher.WEP40))
			{
				EntityItemWifiGroupCipherType gc = wsi.addNewGroupCiphers();
				gc.setStringValue("WEP40");
			}
			if(groupciphers.get(WifiConfiguration.GroupCipher.WEP104))
			{
				EntityItemWifiGroupCipherType gc = wsi.addNewGroupCiphers();
				gc.setStringValue("WEP104");
			}
			if(groupciphers.get(WifiConfiguration.GroupCipher.TKIP))
			{
				EntityItemWifiGroupCipherType gc = wsi.addNewGroupCiphers();
				gc.setStringValue("TKIP");
			}
			if(groupciphers.get(WifiConfiguration.GroupCipher.CCMP))
			{
				EntityItemWifiGroupCipherType gc = wsi.addNewGroupCiphers();
				gc.setStringValue("CCMP");
			}
			
			BitSet keymgt = wc.allowedKeyManagement;
			if(keymgt.get(WifiConfiguration.KeyMgmt.WPA_PSK))
			{
				EntityItemWifiKeyMgmtType km = wsi.addNewKeyManagement();
				km.setStringValue("WPA_PSK");
			}
			if(keymgt.get(WifiConfiguration.KeyMgmt.WPA_EAP))
			{
				EntityItemWifiKeyMgmtType km = wsi.addNewKeyManagement();
				km.setStringValue("WPA_EAP");
			}
			if(keymgt.get(WifiConfiguration.KeyMgmt.NONE))
			{
				EntityItemWifiKeyMgmtType km = wsi.addNewKeyManagement();
				km.setStringValue("NONE");
			}
			if(keymgt.get(WifiConfiguration.KeyMgmt.IEEE8021X))
			{
				EntityItemWifiKeyMgmtType km = wsi.addNewKeyManagement();
				km.setStringValue("IEEE8021X");
			}
			
			BitSet pairwiseCiphers = wc.allowedPairwiseCiphers;
			if(pairwiseCiphers.get(WifiConfiguration.PairwiseCipher.TKIP))
			{
				EntityItemWifiPairwiseCipherType pc = wsi.addNewPairwiseCiphers();
				pc.setStringValue("TKIP");
			}
			if(pairwiseCiphers.get(WifiConfiguration.PairwiseCipher.NONE))
			{
				EntityItemWifiPairwiseCipherType pc = wsi.addNewPairwiseCiphers();
				pc.setStringValue("NONE");
			}
			if(pairwiseCiphers.get(WifiConfiguration.PairwiseCipher.CCMP))
			{
				EntityItemWifiPairwiseCipherType pc = wsi.addNewPairwiseCiphers();
				pc.setStringValue("CCMP");
			}
			
			BitSet allowedProtocols = wc.allowedProtocols;
			if(allowedProtocols.get(WifiConfiguration.Protocol.WPA))
			{
				EntityItemWifiProtocolType ap = wsi.addNewProtocols();
				ap.setStringValue("WPA");
			}
			if(allowedProtocols.get(WifiConfiguration.Protocol.RSN))
			{
				EntityItemWifiProtocolType ap = wsi.addNewProtocols();
				ap.setStringValue("RSN");
			}
			
			EntityItemBoolType ei8 = EntityItemBoolType.Factory
					.newInstance();
			if(wc.hiddenSSID)
				ei8.setStringValue("true");
			else
				ei8.setStringValue("false");
			ei8.setDatatype("boolean");
			wsi.setHiddenSsid(ei8);

			// should be an integer in the schema
			EntityItemIntType ei9 = EntityItemIntType.Factory
					.newInstance();
			ei9.setStringValue(String.valueOf(wc.networkId));
			ei9.setDatatype("int");
			wsi.setNetworkId(ei9);

			// should be an integer in the schema
			EntityItemIntType ei10 = EntityItemIntType.Factory
					.newInstance();
			ei10.setStringValue(String.valueOf(wc.priority));
			ei10.setDatatype("int");
			wsi.setPriority(ei10);

			// should be an integer in the schema
			EntityItemWifiCurrentStatusType ei11 = EntityItemWifiCurrentStatusType.Factory
					.newInstance();
			if(wc.status == WifiConfiguration.Status.CURRENT) { 
				ei11.setStringValue("CURRENT");
				wsi.setCurrentStatus(ei11);
			} else if (wc.status == WifiConfiguration.Status.DISABLED) {
				ei11.setStringValue("DISABLED");
				wsi.setCurrentStatus(ei11);
			} else if (wc.status == WifiConfiguration.Status.ENABLED) {
				ei11.setStringValue("ENABLED");
				wsi.setCurrentStatus(ei11);
			}
		}

		return item_ref;

	}

	public static int generateAppManagerItems(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve app_manager_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		PackageManager pm = c.getPackageManager();
		List<ApplicationInfo> packages = pm
				.getInstalledApplications(PackageManager.GET_META_DATA);
		for (ApplicationInfo ai : packages) {
			// For now collect all applications - future: based on filter
			ReferenceType rt = ot.addNewReference();
			rt.setItemRef(BigInteger.valueOf(item_ref));
	
			ItemType it2 = sd.addNewItem();
			AppManagerItem ami = (AppManagerItem) it2.substitute(
					AppManagerItemDocument.type.getDocumentElementName(),
					AppManagerItem.type);
			ami.setId(BigInteger.valueOf(item_ref)); // Needs to match
														// setItemRef
														// value above
			item_ref++;
			PackageInfo pi = null;
			try {
				pi = pm.getPackageInfo(ai.packageName,
						PackageManager.GET_PERMISSIONS | PackageManager.GET_SIGNATURES | PackageManager.GET_GIDS);
			} catch (NameNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			EntityItemStringType ei1 = EntityItemStringType.Factory
					.newInstance();

			CharSequence appName = ai.loadLabel(pm);
			if (appName != null) {
				ei1.setStringValue(appName.toString());
				ami.setApplicationName(ei1);
			}

			EntityItemStringType ei2 = EntityItemStringType.Factory
					.newInstance();
			ei2.setStringValue(ai.packageName);
			ami.setPackageName(ei2);

			EntityItemStringType ei3 = EntityItemStringType.Factory
					.newInstance();
			ei3.setStringValue(Integer.valueOf(ai.uid).toString());
			ami.setUid(ei3);

			// Data directory
			if(ai.dataDir != null) {
				EntityItemStringType ei4 = EntityItemStringType.Factory
					.newInstance();
				ei4.setStringValue(ai.dataDir);
				ami.setDataDirectory(ei4);
			}
			
			// Version
			if(pi.versionName != null)
			{
				EntityItemStringType ei5 = EntityItemStringType.Factory
					.newInstance();
				ei5.setStringValue(pi.versionName);
				ami.setVersion(ei5);
			}

			// Status (Enabled or Disabled)
			EntityItemBoolType ei6 = EntityItemBoolType.Factory.newInstance();
			boolean enabledBool = ai.enabled;
			if(enabledBool) {
				ei6.setStringValue("true");
				ei6.setDatatype("boolean");
				ami.setCurrentStatus(ei6);
			} else
				Log.d("AndroidSC", "enabledString null");

			// Permissions
			String[] permissions = pi.requestedPermissions;
			if (permissions != null) {
				for (int i = 0; i < permissions.length; i++) {
					EntityItemStringType permission = ami.addNewPermission();
					permission.setStringValue(permissions[i]);
				}
			}

			// Native Lib Dir
			if(ai.nativeLibraryDir != null) {
				EntityItemStringType ei8 = EntityItemStringType.Factory
					.newInstance();
				ei8.setStringValue(ai.nativeLibraryDir);
				ami.setNativeLibDir(ei8);
			}
			
			if(pi.gids != null)
			{
				for(int i = 0; i < pi.gids.length; i++) {
					EntityItemStringType gid = ami.addNewGid();
					gid.setStringValue(String.valueOf(pi.gids[i]));
				}
			}
			
			if(pi.signatures != null)
			{
				for(int i = 0; i < pi.signatures.length; i++) {
					EntityItemBinaryType cert = ami.addNewSigningCertificate();
					cert.setDatatype("binary");
					cert.setStringValue(pi.signatures[i].toCharsString());
				}
			}
			
			EntityItemIntType firstInstall = EntityItemIntType.Factory.newInstance();
			firstInstall.setStringValue(String.valueOf(pi.firstInstallTime));
			firstInstall.setDatatype("int");
			ami.setFirstInstallTime(firstInstall);
			
			EntityItemIntType lastUpdate = EntityItemIntType.Factory.newInstance();
			lastUpdate.setStringValue(String.valueOf(pi.lastUpdateTime));
			lastUpdate.setDatatype("int");
			ami.setLastUpdateTime(lastUpdate);
			
			// ai.sourceDir
			if(ai.sourceDir != null) {
				EntityItemStringType sourceDir = EntityItemStringType.Factory.newInstance();
				sourceDir.setStringValue(ai.sourceDir);
				ami.setPackageFileLocation(sourceDir);
			}
			
		}

		return item_ref;
	}

	public static void generateCertificateItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();

		ot.setComment("Retrieve certificate_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();
		CertificateItem dsi = (CertificateItem) it2.substitute(
				CertificateItemDocument.type.getDocumentElementName(),
				CertificateItem.type);
		dsi.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above
		// Get list of trust anchors (root certificates)
		// Good write-up here: http://nelenkov.blogspot.com/2011/12/ics-trust-store-implementation.html
		
		KeyStore ks;
		try {
			ks = KeyStore.getInstance("AndroidCAStore");
			if(ks != null) {
				ks.load(null, null);
				Enumeration<String> aliases = ks.aliases();
				while (aliases.hasMoreElements()) {
					String alias = aliases.nextElement();
					X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
					byte[] certbytes = cert.getEncoded();
					EntityItemBinaryType cert2 = dsi.addNewTrustedCertificate();
					cert2.setDatatype("binary");
					cert2.setStringValue(getHex(certbytes, null));
				}
			}
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void generateDeviceSettingsItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {
		ObjectType ot = co.addNewObject();

		ot.setComment("Retrieve device_settings_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));

		ItemType it2 = sd.addNewItem();
		DeviceSettingsItem dsi = (DeviceSettingsItem) it2.substitute(
				DeviceSettingsItemDocument.type.getDocumentElementName(),
				DeviceSettingsItem.type);
		dsi.setId(BigInteger.valueOf(item_ref)); // Needs to match setItemRef
													// value above
	
		EntityItemBoolType adb = EntityItemBoolType.Factory.newInstance();
		int adbInt = Settings.Secure.getInt(c.getContentResolver(), Settings.Secure.ADB_ENABLED, 0);
		if(adbInt == 1)
			adb.setStringValue("true");
		else
			adb.setStringValue("false");
		adb.setDatatype("boolean");
		dsi.setAdbEnabled(adb);
		
		EntityItemBoolType mock = EntityItemBoolType.Factory.newInstance();
		int mockInt = Settings.Secure.getInt(c.getContentResolver(), Settings.Secure.ALLOW_MOCK_LOCATION, 0);
		if(mockInt == 1)
			mock.setStringValue("true");
		else
			mock.setStringValue("false");
		mock.setDatatype("boolean");
		dsi.setAllowMockLocation(mock);
		
		EntityItemBoolType nonmarket = EntityItemBoolType.Factory.newInstance();
		int nonmarketInt = Settings.Secure.getInt(c.getContentResolver(), Settings.Secure.INSTALL_NON_MARKET_APPS, 0);
		if(nonmarketInt == 1)
			nonmarket.setStringValue("true");
		else
			nonmarket.setStringValue("false");
		nonmarket.setDatatype("boolean");
		dsi.setInstallNonMarketApps(nonmarket);
	
		// Add getActiveAdmins
		DevicePolicyManager dpm = (DevicePolicyManager) c.getSystemService(Context.DEVICE_POLICY_SERVICE);
		if(dpm != null) {
			List<ComponentName> admins = dpm.getActiveAdmins();
			if(admins != null) {
				for(int i = 0; i < admins.size(); i++ ) {
					EntityItemStringType admin = dsi.addNewDeviceAdmin();
					admin.setStringValue(admins.get(i).getPackageName());
				}
			}
		}
		
		EntityItemBoolType autotime = EntityItemBoolType.Factory.newInstance();
		int autotimeInt = Settings.System.getInt(c.getContentResolver(), Settings.System.AUTO_TIME, 0);
		if(autotimeInt == 1)
			autotime.setStringValue("true");
		else
			autotime.setStringValue("false");
		autotime.setDatatype("boolean");
		dsi.setAutoTime(autotime);
		
		int sdk = Build.VERSION.SDK_INT;
		if(sdk >= 11) {
			// Gather stuff only available in API Level 11 or higher
			Gatherer g = new HoneycombGatherer();
			g.deviceSettings(dsi, c);
		}
		
		EntityItemBoolType usbMassStorage = EntityItemBoolType.Factory.newInstance();
		int usbStorageInt = Settings.System.getInt(c.getContentResolver(), Settings.System.USB_MASS_STORAGE_ENABLED, 0);
		if(usbStorageInt == 1)
			usbMassStorage.setStringValue("true");
		else
			usbMassStorage.setStringValue("false");
		usbMassStorage.setDatatype("boolean");
		dsi.setUsbMassStorageEnabled(usbMassStorage);
		
		try {
			Class<?> c1 = Class.forName("android.os.SELinux");
			Method[] allMethods = c1.getDeclaredMethods();
			
			for(Method m : allMethods) {
				String mname = m.getName();
				if(mname.equals("isSELinuxEnabled")) {
					Object o = m.invoke(null, (Object[]) null);
					EntityItemBoolType selinuxEnabled = EntityItemBoolType.Factory.newInstance();
					selinuxEnabled.setDatatype("boolean");
					if(((Boolean) o).booleanValue() == true)
					{
						selinuxEnabled.setStringValue("true");
					} else {
						selinuxEnabled.setStringValue("false");
					}
					dsi.setSelinuxEnabled(selinuxEnabled);
				}
				
				// SELinux enforcement check may not always work properly, as the SELinux
				// policies may prevent 'untrusted apps' from checking enforcement status,
				// resulting in this always returning false, because in
				// frameworks/base/core/jni/android_os_SELinux.cpp,
				// isSELinuxEnforced returns true if (security_getenforce() == 1) otherwise
				// returns false, but security_getenforce in external/libselinux/src/getenforce.c
				// returns -1 if the enforcement status cannot be obtained.
				if(mname.equals("isSELinuxEnforced")) {
					Object o = m.invoke(null, (Object[]) null);
					EntityItemBoolType selinuxEnforcing = EntityItemBoolType.Factory.newInstance();
					selinuxEnforcing.setDatatype("boolean");
					if(((Boolean) o).booleanValue() == true)
					{
						selinuxEnforcing.setStringValue("true");
					} else {
						selinuxEnforcing.setStringValue("false");
					}
					dsi.setSelinuxEnforcing(selinuxEnforcing);
				}
			}
		// In the exception cases, should we assume SELinux is not present
		// and set both values to false?
		} catch (ClassNotFoundException e) {

		} catch (IllegalArgumentException e) {

		} catch (IllegalAccessException e) {

		} catch (InvocationTargetException e) {

		}
		
		
	}		
	
	public static void generateTelephonyItem(CollectedObjectsType co,
			SystemDataType sd, String id, int item_ref, Context c) {

		ObjectType ot = co.addNewObject();
		ot.setComment("Retrieve telephony_item");
		ot.setFlag(FlagEnumeration.COMPLETE); // Fix
		ot.setId(id);
		ot.setVersion(BigInteger.ONE); // Fix

		ReferenceType rt = ot.addNewReference();
		rt.setItemRef(BigInteger.valueOf(item_ref));
		ItemType it2 = sd.addNewItem();

		TelephonyItem ti = (TelephonyItem) it2.substitute(
				TelephonyItemDocument.type.getDocumentElementName(), TelephonyItem.type);
		ti.setId(BigInteger.valueOf(item_ref));
		
		TelephonyManager tm = (TelephonyManager) c.getSystemService(Context.TELEPHONY_SERVICE);
		if (tm == null)
			return;

		EntityItemNetworkType networkType = EntityItemNetworkType.Factory.newInstance();
		int networkTypeInt = tm.getNetworkType();
		if(networkTypeInt == TelephonyManager.NETWORK_TYPE_1xRTT) {
			networkType.setStringValue("1xRTT");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_CDMA) {
			networkType.setStringValue("CDMA");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_EDGE) {
			networkType.setStringValue("EDGE");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_EHRPD) {
			networkType.setStringValue("EHRPD");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_EVDO_0) {
			networkType.setStringValue("EVDO-0");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_EVDO_A) {
			networkType.setStringValue("EVDO-A");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_EVDO_B) {
			networkType.setStringValue("EVDO-B");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_GPRS) {
			networkType.setStringValue("GPRS");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_HSDPA) {
			networkType.setStringValue("HSDPA");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_HSPA) {
			networkType.setStringValue("HSPA");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_HSPAP) { // Requires API Level 13
			networkType.setStringValue("HSPAP");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_HSUPA) {
			networkType.setStringValue("HSUPA");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_IDEN) {
			networkType.setStringValue("IDEN");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_LTE) { // Requires API Level 11
			networkType.setStringValue("LTE");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_UMTS) {
			networkType.setStringValue("UMTS");
			ti.setNetworkType(networkType);
		}
		else if(networkTypeInt == TelephonyManager.NETWORK_TYPE_UNKNOWN) {
			networkType.setStringValue("UNKNOWN");
			ti.setNetworkType(networkType);
		}

		EntityItemStringType simCountryIso = EntityItemStringType.Factory.newInstance();
		if((tm.getSimCountryIso() != null) && (!tm.getSimCountryIso().equals(""))) {
			simCountryIso.setStringValue(tm.getSimCountryIso());
			ti.setSimCountryIso(simCountryIso);
		}
		
		EntityItemStringType simOperatorCode = EntityItemStringType.Factory.newInstance();
		if((tm.getSimOperator() != null) && (!tm.getSimOperator().equals(""))) {
			simOperatorCode.setStringValue(tm.getSimOperator());
			ti.setSimOperatorCode(simOperatorCode);
		}
	}
}
