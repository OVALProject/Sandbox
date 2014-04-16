//
//
//****************************************************************************************//
// Copyright (c) 2002-2014, The MITRE Corporation
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

import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemBoolType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemIntType;
import org.mitre.oval.xmlSchema.xAndroidSystemCharacteristics.CameraItemDocument.CameraItem;
import org.mitre.oval.xmlSchema.xAndroidSystemCharacteristics.DeviceSettingsItemDocument.DeviceSettingsItem;
import org.mitre.oval.xmlSchema.xAndroidSystemCharacteristics.EncryptionItemDocument.EncryptionItem;
import org.mitre.oval.xmlSchema.xAndroidSystemCharacteristics.EntityItemEncryptionStatusType;
import org.mitre.oval.xmlSchema.xAndroidSystemCharacteristics.PasswordItemDocument.PasswordItem;
import android.annotation.TargetApi;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;

@TargetApi(Build.VERSION_CODES.HONEYCOMB)
public class HoneycombGatherer extends Gatherer {
	void deviceSettings(DeviceSettingsItem dsi, Context c)
	{
		EntityItemBoolType autotimezone = EntityItemBoolType.Factory.newInstance();
		int autotimezoneInt = Settings.System.getInt(c.getContentResolver(), Settings.System.AUTO_TIME_ZONE, 0);
		if(autotimezoneInt == 1)
			autotimezone.setStringValue("true");
		else
			autotimezone.setStringValue("false");
		autotimezone.setDatatype("boolean");
		dsi.setAutoTimeZone(autotimezone);
	}
	
	void password(PasswordItem pi, DevicePolicyManager dpm) {
		EntityItemIntType ei3 = EntityItemIntType.Factory.newInstance();
		ei3.setStringValue(Integer.valueOf(dpm.getPasswordHistoryLength(null))
				.toString());
		ei3.setDatatype("int");
		pi.setPasswordHist(ei3); // API Level 11

		
		// Only applies if password quality is PASSWORD_QUALITY_COMPLEX
		EntityItemIntType ei5 = EntityItemIntType.Factory.newInstance();
		ei5.setStringValue(Integer.valueOf(dpm.getPasswordMinimumLetters(null))
				.toString());
		ei5.setDatatype("int");
		pi.setPasswordMinLetters(ei5); // API Level 11

		// Only applies if password quality is PASSWORD_QUALITY_COMPLEX
		EntityItemIntType ei6 = EntityItemIntType.Factory.newInstance();
		ei6.setStringValue(Integer.valueOf(
				dpm.getPasswordMinimumLowerCase(null)).toString());
		ei6.setDatatype("int");
		pi.setPasswordMinLowerCaseLetters(ei6); // API Level 11

		// Only applies if password quality is PASSWORD_QUALITY_COMPLEX
		EntityItemIntType ei7 = EntityItemIntType.Factory.newInstance();
		ei7.setStringValue(Integer.valueOf(
				dpm.getPasswordMinimumNonLetter(null)).toString());
		ei7.setDatatype("int");
		pi.setPasswordMinNonLetters(ei7); // API Level 11

		// Only applies if password quality is PASSWORD_QUALITY_COMPLEX
		EntityItemIntType ei8 = EntityItemIntType.Factory.newInstance();
		ei8.setStringValue(Integer.valueOf(dpm.getPasswordMinimumNumeric(null))
				.toString());
		ei8.setDatatype("int");
		pi.setPasswordMinNumeric(ei8); // API Level 11

		// Only applies if password quality is PASSWORD_QUALITY_COMPLEX
		EntityItemIntType ei9 = EntityItemIntType.Factory.newInstance();
		ei9.setStringValue(Integer.valueOf(dpm.getPasswordMinimumSymbols(null))
				.toString());
		ei9.setDatatype("int");
		pi.setPasswordMinSymbols(ei9); // API Level 11

		// Only applies if password quality is PASSWORD_QUALITY_COMPLEX
		EntityItemIntType ei10 = EntityItemIntType.Factory.newInstance();
		ei10.setStringValue(Integer.valueOf(
				dpm.getPasswordMinimumUpperCase(null)).toString());
		ei10.setDatatype("int");
		pi.setPasswordMinUpperCaseLetters(ei10); // API Level 11

		EntityItemIntType ei11 = EntityItemIntType.Factory.newInstance();
		ei11.setStringValue(String.valueOf(
				dpm.getPasswordExpirationTimeout(null)));
		ei11.setDatatype("int");
		pi.setPasswordExpirationTimeout(ei11); // API Level 11

	}

	void camera(CameraItem ci, DevicePolicyManager dpm) {
	}
	
	void encryption(EncryptionItem ei, DevicePolicyManager dpm) {
		EntityItemBoolType ei1 = EntityItemBoolType.Factory.newInstance();
		ei1.setStringValue(Boolean.toString(dpm.getStorageEncryption(null))); // API
																				// Level
																			// 11
		ei1.setDatatype("boolean");
		ei.setEncryptionPolicyEnabled(ei1);
		
		EntityItemEncryptionStatusType ei2 = EntityItemEncryptionStatusType.Factory.newInstance();

		int status = dpm.getStorageEncryptionStatus();
		if(status == DevicePolicyManager.ENCRYPTION_STATUS_UNSUPPORTED) {
			ei2.setStringValue("ENCRYPTION_STATUS_UNSUPPORTED");
			ei.setEncryptionStatus(ei2);
		} else if (status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVATING) {
			ei2.setStringValue("ENCRYPTION_STATUS_ACTIVATING");
			ei.setEncryptionStatus(ei2);
		} else if (status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE) {
			ei2.setStringValue("ENCRYPTION_STATUS_ACTIVE");
			ei.setEncryptionStatus(ei2);
		} else if (status == DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE) {
			ei2.setStringValue("ENCRYPTION_STATUS_INACTIVE");
			ei.setEncryptionStatus(ei2);
		}
		
	

	}
}
