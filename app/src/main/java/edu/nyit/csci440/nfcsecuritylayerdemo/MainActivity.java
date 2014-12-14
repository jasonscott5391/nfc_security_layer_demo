package edu.nyit.csci440.nfcsecuritylayerdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Point;
import android.nfc.NdefMessage;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.os.Bundle;
import android.os.Parcelable;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;
import android.widget.TextView;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.Date;


public class MainActivity extends Activity implements NfcAdapter.CreateNdefMessageCallback,
        NfcAdapter.OnNdefPushCompleteCallback {

    private TextView mStatusTextView;

    private Point mDimension;

    private Certificate mCaCertificate;

    private Certificate mUserCertificate;

    private Certificate mOtherPartyCertificate;

    private KeyStore mKeyStore;

    private PrivateKey mPrivateKey;

    private boolean mTrust = false;

    private static final String SNFC = " SNFC>";

    private byte[] mData;

    private NfcAdapter mNfcAdapter;

    private static final int MESSAGE_SENT = 1;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mDimension = new Point();
        getWindowManager().getDefaultDisplay().getSize(mDimension);

        mStatusTextView = (TextView) findViewById(R.id.nfc_status);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        if (mNfcAdapter == null) {
            mStatusTextView.setText("NFC is not available on this device.");
        } else {
            // Register callback to set NDEF message
            mNfcAdapter.setNdefPushMessageCallback(this, this);
            // Register callback to listen for message-sent success
            mNfcAdapter.setOnNdefPushCompleteCallback(this, this);
        }

        printConsole(" initializing...");
        initCertificates();

        printConsole("verifying CA certificate...");
        verifyCertificateAuthority();

        printConsole("verifying device certificate...");
        verifyUserCertificate();

        setUserPrivateKey();
    }

    @Override
    protected void onResume() {
        super.onResume();

        printConsole(" waiting...");
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processIntent(getIntent());
        }
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
                viewDataTextDialog();
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

    @Override
    public NdefMessage createNdefMessage(NfcEvent event) {
        byte[] messageData = packageSecureMessage();
        return null;
    }

    @Override
    public void onNdefPushComplete(NfcEvent event) {
        printConsole(" attachment sent...");
    }

    @Override
    public void onNewIntent(Intent intent) {
        // onResume gets called after this to handle the intent
        setIntent(intent);
    }

    /**
     * Parses the NDEF Message from the intent and prints to the TextView
     */
    void processIntent(Intent intent) {
        Parcelable[] rawMsgs = intent.getParcelableArrayExtra(
                NfcAdapter.EXTRA_NDEF_MESSAGES);
        // only one message sent during the beam
        NdefMessage msg = (NdefMessage) rawMsgs[0];
        // record 0 contains the MIME type, record 1 is the AAR, if present
        //TODO (jasonscott) Securely unpack message.
        //TODO (jasonscott) Print message to textview.
//        mInfoText.setText(new String(msg.getRecords()[0].getPayload()));
    }

    /**
     * Load CA certificate, create KeyStore with user KeyStore, and
     * load user certificate.
     *
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
            printConsole("CA certificate verified...");
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
            printConsole("device certificate verified...");
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
     *
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
     *
     * @param certificate Specified certificate.
     * @param data        Specified data.
     * @param signedData  Specified signedData.
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

    private byte[] packageSecureMessage() {
        byte[] data = null;
        //TODO (jasonscott) Design message format so that app knows how to dismantle.
        //TODO (jasonscott) CA cert, SignedData, and data;
        String message = mCaCertificate.toString();

        return data;
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
                        printConsole(" attachment verified...");
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        printConsole(" attachment invalid, discarding...");
                    }
                }).show();

    }

    private void viewDataTextDialog() {
        final EditText dataText = new EditText(this);

        final AlertDialog alertDialog = new AlertDialog.Builder(this)
                .setTitle("Data Entry")
                .setMessage("Enter data...")
                .setView(dataText)
                .setPositiveButton("Enter", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String dataString = dataText.getText().toString();
                        if (dataString != null || !dataString.equals("")) {
                            mData = dataText.getText().toString().getBytes();
                            printConsole(" securing attachment...");
                        }
                    }
                }).setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        printConsole(" waiting...");
                    }
                }).show();

    }

    private String getDateTimeStamp() {
        SimpleDateFormat format =
                new SimpleDateFormat("MM-dd-yy hh:mm:ss");
        Date date = new Date();

        return format.format(date);
    }

    private void printConsole(String message) {
        String text = mStatusTextView.getText().toString();
        text += "\n" + getDateTimeStamp() + SNFC + message;
        mStatusTextView.setText(text);
    }

}
