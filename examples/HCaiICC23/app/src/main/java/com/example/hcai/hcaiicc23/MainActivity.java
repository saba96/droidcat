package com.example.hcai.hcaiicc23;

import android.Manifest;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.telephony.TelephonyManager;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Toast;

import java.util.LinkedList;
import java.util.List;
import java.util.Random;

public class MainActivity extends AppCompatActivity implements ActivityCompat.OnRequestPermissionsResultCallback {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    public void onClickBtn(View v)
    {
        //Toast.makeText(this, "Clicked on Button", Toast.LENGTH_LONG).show();
        if (ContextCompat.checkSelfPermission(this,
                Manifest.permission.READ_PHONE_STATE)
                != PackageManager.PERMISSION_GRANTED) {

            // Should we show an explanation?
            if (ActivityCompat.shouldShowRequestPermissionRationale(this,
                    Manifest.permission.READ_PHONE_STATE)) {

                ReceiveActivity.msbox(this, "hcai prompt in MainActivity", "You have previously deined giving this app " +
                        "the permission for accessing phone state, which is however required for this app!" );

            } else {

                // No explanation needed, we can request the permission.
                ReceiveActivity.msbox(this, "hcai prompt in MainActivity", "This the first time this app asks for " +
                        "the permission for accessing phone state.");
                // MY_PERMISSIONS_REQUEST_READ_CONTACTS is an
                // app-defined int constant. The callback method gets the
                // result of the request.

            }
            ActivityCompat.requestPermissions(this,
                    new String[]{Manifest.permission.READ_PHONE_STATE},
                    0x12);
        }
        else {
            TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
            String imei = telephonyManager.getDeviceId(); //source

            Intent i = new Intent(this, ReceiveActivity.class);
            i.putExtra("DroidBench", imei);

            List<Intent> iList = new LinkedList<Intent>();
            iList.add(i);

            Intent i2 = iList.get(0);

            startActivity(i2);
        }
    }

    public void onClickBtnClose(View v)
    {
        System.exit(0);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode,
                                           String permissions[], int[] grantResults) {
        switch (requestCode) {
            case 0x12: {
                TelephonyManager telephonyManager = (TelephonyManager) getSystemService(Context.TELEPHONY_SERVICE);
                String imei = "";
                // If request is cancelled, the result arrays are empty.

                if (grantResults.length > 0
                        && grantResults[0] == PackageManager.PERMISSION_GRANTED) {

                    // permission was granted, yay! Do the
                    // contacts-related task you need to do.

                    ReceiveActivity.msbox(this, "Hcai prompt in MainActivity", "OK, you granted the permission. So an intent with" +
                            " a this phone's IMEI be sent out");
                    imei=telephonyManager.getDeviceId(); //source

                } else {

                    // permission denied, boo! Disable the
                    // functionality that depends on this permission.
                    ReceiveActivity.msbox(this, "Hcai prompt in MainActivity", "OK, you denied the permission. So an intent with" +
                            " a random IMEI be sent out - grantResults.length = " + (grantResults.length) +
                            " grantResults[0] == PackageManager.PERMISSION_GRANTED = " +
                            (grantResults[0] == PackageManager.PERMISSION_GRANTED) +
                            " grantResults[0] = " + grantResults[0]);
                    imei= ""+(new Random().nextLong());
                }


                Intent i = new Intent(this, ReceiveActivity.class);
                i.putExtra("DroidBench", imei);

                List<Intent> iList = new LinkedList<Intent>();
                iList.add(i);

                Intent i2 = iList.get(0);

                //startActivity(i2);

                return;
            }
            default:
                return;

            // other 'case' lines to check for other
            // permissions this app might request
        }
    }
}

