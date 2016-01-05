package com.example.hcai.hcaiicc21;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.view.View;
import android.widget.Toast;

import java.util.LinkedList;
import java.util.List;

public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onClickBtn(View v)
    {
        //Toast.makeText(this, "Clicked on Button", Toast.LENGTH_LONG).show();
        TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
        String imei = telephonyManager.getDeviceId(); //source

        Intent i = new Intent(this, ReceiveActivity.class);
        i.putExtra("DroidBench", imei);

        List<Intent> iList = new LinkedList<Intent>();
        iList.add(i);

        Intent i2 = iList.get(0);

        startActivity(i2);
    }

    public void onClickBtnClose(View v)
    {
        System.exit(0);
    }
}

