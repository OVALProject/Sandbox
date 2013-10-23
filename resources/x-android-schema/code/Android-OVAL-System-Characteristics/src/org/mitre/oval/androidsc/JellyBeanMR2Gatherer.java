package org.mitre.oval.androidsc;

import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5.EntityItemBoolType;
import org.mitre.oval.xmlSchema.ovalSystemCharacteristics5Android.SystemDetailsItemDocument.SystemDetailsItem;

import android.security.KeyChain;

public class JellyBeanMR2Gatherer extends JellyBeanMR1Gatherer {
	void systemDetails(SystemDetailsItem sdi)
	{
		EntityItemBoolType hardwareKeystore = EntityItemBoolType.Factory.newInstance();
		boolean boundKey = KeyChain.isBoundKeyAlgorithm("RSA");
		if(boundKey == true) {
			hardwareKeystore.setDatatype("boolean");
			hardwareKeystore.setStringValue("true");
		}
		else {
			hardwareKeystore.setDatatype("boolean");
			hardwareKeystore.setStringValue("false");
		}
		sdi.setHardwareKeystore(hardwareKeystore);
		
	}
}
