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

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;

public class AndroidSCActivity extends Activity {

	private TestFileTextBox mTestFile;
	private OutputFileTextBox mOutputFile;

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		LinearLayout ll = new LinearLayout(this);
		ll.setOrientation(1); // vertical
		Button mGenerateButton = new GenerateButton(this);
		ll.addView(mGenerateButton, new LinearLayout.LayoutParams(
				ViewGroup.LayoutParams.WRAP_CONTENT,
				ViewGroup.LayoutParams.WRAP_CONTENT, 0));
		mTestFile = new TestFileTextBox(this);
		mOutputFile = new OutputFileTextBox(this);
		ll.addView(mTestFile, new LinearLayout.LayoutParams(
				ViewGroup.LayoutParams.WRAP_CONTENT,
				ViewGroup.LayoutParams.WRAP_CONTENT, 0));
		ll.addView(mOutputFile, new LinearLayout.LayoutParams(
				ViewGroup.LayoutParams.WRAP_CONTENT,
				ViewGroup.LayoutParams.WRAP_CONTENT, 0));
		
		setContentView(ll);
	}

	class TestFileTextBox extends EditText {
		public TestFileTextBox(Context ctx) {
			super(ctx);
			this.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
			this.setHint("Input test file");
			setText("android-test.xml");
			
		}
	}

	class OutputFileTextBox extends EditText {
		public OutputFileTextBox(Context ctx) {
			super(ctx);
			this.setInputType(InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
			this.setHint("Output system char file");
			setText("android-system-char.xml");
			
		}
	}

	class GenerateButton extends Button {
		// Jumps directly into Document Manager's main menu, skipping the login
		// screen

		OnClickListener clicker = new OnClickListener() {
			@Override
			public void onClick(View v) {
				GenerateAndroidSC.generate(AndroidSCActivity.this,
						mTestFile.getText().toString(), mOutputFile.getText().toString());
			}
		};

		public GenerateButton(Context ctx) {
			super(ctx);
			setText("Generate System Characteristics");
			setOnClickListener(clicker);
		}
	}

}
