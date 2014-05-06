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
import org.mitre.oval.xmlSchema.xAndroidSystemCharacteristics.SystemDetailsItemDocument.SystemDetailsItem;
import android.annotation.TargetApi;
import android.os.Build;
import android.security.KeyChain;

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
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
