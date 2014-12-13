package edu.nyit.csci440.nfcsecuritylayerdemo;

import android.app.AlertDialog;
import android.content.DialogInterface;
import android.graphics.Point;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.ViewGroup;
import android.widget.ListView;
import android.widget.RelativeLayout;
import android.widget.TextView;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class MainActivity extends ActionBarActivity {

    private RelativeLayout mStatusLayout;

    private RelativeLayout mHistoryLayout;

    private TextView mStatusTextView;

    private ListView mHistoryListView;

    private Point mDimension;

    private Certificate mCaCertificate;

    private Certificate mUserCertificate;

    private Certificate mOtherPartyCertificate;

    private KeyStore mKeyStore;

    private PrivateKey mPrivateKey;

    private boolean mTrust = false;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mDimension = new Point();
        getWindowManager().getDefaultDisplay().getSize(mDimension);

        mStatusLayout = (RelativeLayout) findViewById(R.id.status_layout);
        mHistoryLayout = (RelativeLayout) findViewById(R.id.history_layout);

        RelativeLayout.LayoutParams statusLayoutParams =
                new RelativeLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (mDimension.y / 2));

        RelativeLayout.LayoutParams historyLayoutParams =
                new RelativeLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, (mDimension.y / 2));
        historyLayoutParams.addRule(RelativeLayout.BELOW, R.id.status_layout);

        mStatusLayout.setLayoutParams(statusLayoutParams);
        mHistoryLayout.setLayoutParams(historyLayoutParams);

        mStatusTextView = (TextView) findViewById(R.id.nfc_status);
        mHistoryListView = (ListView) findViewById(R.id.nfc_history);

        initCertificates();

        verifyCertificateAuthority();
        verifyUserCertificate();

        setUserPrivateKey();

    }

    /**
     * Load CA certificate, create KeyStore with user KeyStore, and
     * load user certificate.
     * @throws Exception
     */
    private void initCertificates() {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream caInput = getResources().openRawResource(R.raw.csci440);
            mCaCertificate = cf.generateCertificate(caInput);

            mKeyStore = KeyStore.getInstance("PKCS12");
            mKeyStore.load(null);

            InputStream inputStream = getResources().openRawResource(R.raw.devicebkeystore);
            mKeyStore.load(inputStream, "deviceb".toCharArray());
            mUserCertificate = mKeyStore.getCertificate("deviceb");

        } catch (Exception e) {
            Log.e("initCertificates", e.getMessage());
        }
    }

    /**
     * Verifies that the CA certificate hasn't been modified.
     */
    private void verifyCertificateAuthority() {
        try {
            mCaCertificate.verify(mCaCertificate.getPublicKey());
            setCaCertificate();
        } catch (Exception e) {
            Log.e("verifyCertificateAuthority", e.getMessage());

        }
    }

    /**
     * Verifies that the user certificate has been signed by the CA.
     */
    private void verifyUserCertificate() {
        try {
            mUserCertificate.verify(mCaCertificate.getPublicKey());
        } catch (Exception e) {
            Log.e("verifyUserCertificate", e.getMessage());

        }
    }

    /**
     * Stores the CA certificate in the KeyStore.
     */
    private void setCaCertificate() {
        try {
            mKeyStore.setCertificateEntry("ca", mCaCertificate);
        } catch (Exception e) {
            Log.e("setCaCertificate", e.getMessage());
        }
    }

    /**
     * Sets the users private key from the KeyStore.
     */
    private void setUserPrivateKey() {
        try {
            mPrivateKey = (PrivateKey) mKeyStore.getKey("deviceb", "deviceb".toCharArray());
        } catch (Exception e) {
            Log.e("getUserPrivateKey", e.getMessage());
        }
    }

    /**
     * Returns a digital signature of the specified data with the users private key.
     * @param data Specified data.
     * @return Digital Signatures in bytes.
     */
    private byte[] signData(byte[] data) {
        byte[] signedData = null;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(mPrivateKey);
            signature.update(data);

            signedData = signature.sign();
        } catch (Exception e) {
            Log.e("signData", e.getMessage());
        }

        return signedData;
    }

    /**
     * Verifies that the specified digital signature, was signed with the specified certificate, and
     * matches the specified plain data.
     * @param certificate Specified certificate.
     * @param data Specified data.
     * @param signedData Specified signedData.
     * @return Whether the digital signature is valid.
     */
    private boolean verifySignedData(Certificate certificate, byte[] data, byte[] signedData) {
        boolean valid = false;

        try {

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(certificate);
            signature.update(data);
            valid = signature.verify(signedData);

        } catch (Exception e) {
            Log.e("verifySignedData", e.getMessage());
        }

        return valid;
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {

        switch (item.getItemId()) {
            case R.id.action_attach:
                //TODO (jasonscott) Choose file for attachment.
                break;

            case R.id.action_view_ca:
                if (mCaCertificate != null) {
                    viewCertificateAuthorityDialog();
                }
                break;

            default:
                break;
        }

        return super.onOptionsItemSelected(item);
    }

    /**
     * Displays a dialog viewing the CA Certificate.
     */
    private void viewCertificateAuthorityDialog() {
        final AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Certificate Authority")
                .setMessage(mCaCertificate.toString())
                .setNeutralButton("Ok", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                    }
                }).show();

    }

    /**
     * Shows the dialog for the
     */
    private void viewCertificateDialog(Certificate certificate) {
        final AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Trust Other Party?")
                .setMessage(certificate.toString())
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                       mTrust = true;
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        mTrust = false;
                    }
                }).show();
    }
}
