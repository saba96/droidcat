package com.example.hcai.hcaiicc21;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

public class ReceiveActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_receive);

        Intent i = getIntent();
        String imei = i.getStringExtra("DroidBench");
        Log.i("DroidBench", imei);
        msbox("hcai prompt", "Intent content received: " + i);
    }

    public void msbox(String str,String str2)
    {
        AlertDialog.Builder dlgAlert  = new AlertDialog.Builder(this);
        dlgAlert.setTitle(str);
        dlgAlert.setMessage(str2);
        dlgAlert.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                finish();
            }
        });
        dlgAlert.setCancelable(true);
        dlgAlert.create().show();
    }
}
