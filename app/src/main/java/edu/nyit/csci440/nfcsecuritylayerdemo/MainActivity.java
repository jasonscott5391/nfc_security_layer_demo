package edu.nyit.csci440.nfcsecuritylayerdemo;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Point;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.NfcEvent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.Parcelable;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.text.SimpleDateFormat;
import java.util.Arrays;
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

    private String mAlias;

    private String mPassword;

    private byte[] mData;

    private byte[] mSecuredData;

    private NfcAdapter mNfcAdapter;

    private static final int MESSAGE_SENT = 1;

    private SharedPreferences mSharedPreferences;

    private static final int CERT_LEN = 1006;

    private static final int SIG_LEN = 256;

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

        //TODO (jasonscott) Login dialog at start.  Device A or Device B.
        //TODO (jasonscott) Logout in menu to bring login dialog up and restart the activity.
    }

    @Override
    protected void onResume() {
        super.onResume();

        mSharedPreferences = getSharedPreferences("user_preferences", 0);
        mAlias = mSharedPreferences.getString("alias", null);
        mPassword = mSharedPreferences.getString("password", null);
        String history = mSharedPreferences.getString("history", null);

        if (history != null) {
            mStatusTextView.setText(history);
        }

        if (mAlias == null || mPassword == null) {
            viewLoginDialog();
        } else {
            initialize();
        }

        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processIntent(getIntent());
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        SharedPreferences.Editor preferencesEditor = mSharedPreferences.edit();
        preferencesEditor.putString("alias", mAlias);
        preferencesEditor.putString("password", mPassword);
        preferencesEditor.putString("history", mStatusTextView.getText().toString());
        preferencesEditor.apply();
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

            case R.id.action_login:
                mAlias = null;
                mPassword = null;
                mStatusTextView.setText("");
                this.recreate();
            default:
                break;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public NdefMessage createNdefMessage(NfcEvent event) {
        NdefMessage ndefMessage = null;
        if (mSecuredData != null) {
            ndefMessage = new NdefMessage(NdefRecord.createMime(
                    "application/edu.nyit.csci440.nfcsecuritylayerdemo",
                    mSecuredData)
//                    , NdefRecord.createApplicationRecord("edu.nyit.csci440.nfcsecuritylayerdemo")
            );
        }
        return ndefMessage;
    }

    @Override
    public void onNdefPushComplete(NfcEvent event) {
        printConsole(" attachment sent...");
        mHandler.obtainMessage(MESSAGE_SENT).sendToTarget();
    }

    /**
     * This handler receives a message from onNdefPushComplete
     */
    private final Handler mHandler = new Handler() {
        @Override
        public void handleMessage(Message msg) {
            switch (msg.what) {
                case MESSAGE_SENT:
                    Toast.makeText(getApplicationContext(), "Message sent!", Toast.LENGTH_LONG).show();
                    break;
            }
        }
    };

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
        unpackSecuredNdef(msg);
    }

    private void initialize() {
        printConsole(" initializing...");
        initCertificates();

        printConsole("verifying CA certificate...");
        verifyCertificateAuthority();

        printConsole("verifying device certificate...");
        verifyUserCertificate();

        setUserPrivateKey();

        printConsole(" waiting...");
        if (NfcAdapter.ACTION_NDEF_DISCOVERED.equals(getIntent().getAction())) {
            processIntent(getIntent());
        }
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

            int resId;
            if (mAlias.equals("devicea")) {
                resId = R.raw.deviceakeystore;
            } else {
                resId = R.raw.devicebkeystore;
            }

            InputStream inputStream = getResources().openRawResource(resId);
            mKeyStore.load(inputStream, mPassword.toCharArray());
            mUserCertificate = mKeyStore.getCertificate(mAlias);

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
            printConsole("CA certificate corrupted or invalid, remove this application...");
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
            printConsole("This users certificate is corrupted or invalid, you will be logged out...");
            this.recreate();
        }
    }

    private void verifyOtherUserCertificate() {
        try {
            mOtherPartyCertificate.verify(mCaCertificate.getPublicKey());
            printConsole("device certificate verified...");
        } catch (Exception e) {
            Log.e("verifyUserCertificate", e.getMessage());
            printConsole(" This other users certificate is corrupted or invalid, message discarded...");
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
            mPrivateKey = (PrivateKey) mKeyStore.getKey(mAlias, mPassword.toCharArray());
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

            printConsole(" Signing data...");
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
            printConsole(" Verifying digital signature...");
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(certificate);
            signature.update(data);
            valid = signature.verify(signedData);

        } catch (Exception e) {
            Log.e("verifySignedData", e.getMessage());
            printConsole(" Digital signature corrupted or invalid...");
        }

        return valid;
    }

    /**
     * Returns the concatenated user certificate, digital signature,
     * and data.
     *
     * @return Byte array of data package.
     */
    private byte[] packageData() {
        ByteArrayOutputStream byteStream = null;

        printConsole(" Packaging attachment...");

        if (mData != null) {
            try {

                byteStream = new ByteArrayOutputStream();

                byte[] userCertEncoded = mUserCertificate.getEncoded();
                byte[] signature;
                signature = signData(mData);

                byteStream.write(userCertEncoded);
                byteStream.write(signature);
                byteStream.write(mData);

            } catch (Exception e) {
                Log.e("createNdefMessage", e.getMessage());
            }
        }

        return byteStream.toByteArray();
    }

    /**
     * Unpacks the specified Secured Ndef message and verifies sender and data.
     *
     * @param ndefMessage The specified Ndef message.
     */
    private void unpackSecuredNdef(NdefMessage ndefMessage) {
        try {
            byte[] payload = ndefMessage.getRecords()[0].getPayload();
            int payloadLen = payload.length;
            byte[] otherPartyCert = Arrays.copyOfRange(payload, 0, CERT_LEN);
            byte[] signature = Arrays.copyOfRange(payload, CERT_LEN, (CERT_LEN + SIG_LEN));
            byte[] data = Arrays.copyOfRange(payload, (CERT_LEN + SIG_LEN), payloadLen);

            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            mOtherPartyCertificate = cf.generateCertificate(new ByteArrayInputStream(otherPartyCert));
            verifyOtherUserCertificate();

            verifySignedData(mOtherPartyCertificate, data, signature);

            String message = new String(data, "UTF-8");
            printConsole(message);

        } catch (Exception e) {
            Log.e("unpackSecureNdef", e.getMessage());
        }
    }

    /**
     * Displays a dialog to login accepting the correct
     * alias and password combination.
     */
    private void viewLoginDialog() {


        LinearLayout linearLayout = new LinearLayout(this);
        linearLayout.setOrientation(LinearLayout.VERTICAL);
        final EditText aliasEditText = new EditText(this);
        aliasEditText.setHint("Alias");
        final EditText passwordEditText = new EditText(this);
        passwordEditText.setHint("Password");

        linearLayout.addView(aliasEditText);
        linearLayout.addView(passwordEditText);

        final AlertDialog loginDialog = new AlertDialog.Builder(this)
                .setTitle("Login")
                .setView(linearLayout)
                .setNeutralButton("Enter", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        String alias = aliasEditText.getText().toString();
                        String password = passwordEditText.getText().toString();
                        if (alias != null && password != null) {
                            mAlias = alias;
                            mPassword = password;
                            initialize();
                        }
                    }
                }).show();
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
     * Shows a dialog viewing the certificate in the secure ndef message.
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

    /**
     * Creates dialog for getting user input message.
     */
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
                            mSecuredData = packageData();
                        }
                    }
                }).setNegativeButton("Cancel", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        printConsole(" waiting...");
                    }
                }).show();

    }

    /**
     * Returns a formatted String for the current date and time.
     *
     * @return Current date and time.
     */
    private String getDateTimeStamp() {
        SimpleDateFormat format =
                new SimpleDateFormat("MM-dd-yy hh:mm:ss");
        Date date = new Date();

        return format.format(date);
    }

    /**
     * Outputs the specified message to status console on device.
     *
     * @param message The specified message.
     */
    private void printConsole(String message) {
        String text = mStatusTextView.getText().toString();
        text += "\n" + getDateTimeStamp() + SNFC + message;
        mStatusTextView.setText(text);
    }

}
