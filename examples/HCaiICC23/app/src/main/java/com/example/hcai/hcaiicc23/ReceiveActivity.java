package com.example.hcai.hcaiicc23;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

public class ReceiveActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_receive);

        Intent i = getIntent();
        String imei = i.getStringExtra("DroidBench");
        Log.i("DroidBench", imei);
        msbox(this, "hcai prompt", "Intent content received: " + i);
    }

    public static void msbox(final Activity a, String str,String str2)
    {
        AlertDialog.Builder dlgAlert  = new AlertDialog.Builder(a);
        dlgAlert.setTitle(str);
        dlgAlert.setMessage(str2);
        dlgAlert.setPositiveButton("OK", new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int whichButton) {
                if (a instanceof MainActivity) {a.setVisible(true); a.setContentView(R.layout.activity_main);}
                else { a.finish(); }

            }
        });
        dlgAlert.setCancelable(true);
        dlgAlert.create().show();
    }
}
