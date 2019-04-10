package edu.buffalo.cse.cse486586.simpledht;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.MatrixCursor;
import android.database.MergeCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.telephony.TelephonyManager;
import android.util.Log;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;
import java.io.File;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.PriorityQueue;
import java.util.ArrayList;
import java.util.TreeMap;
import android.content.ContentProvider;
import android.database.Cursor;

public class SimpleDhtProvider extends ContentProvider {

    static final String TAG = SimpleDhtProvider.class.getSimpleName();

    static String[] REMOTE_PORTS = {"11108", "11112", "11116", "11120", "11124"};
    static final int SERVER_PORT = 10000;
    HashMap<String, String> map = new HashMap<String, String>();
    public static String myPortId = "";
    public static String mySocketId = "";
    public static String predessor = "";
    public static String successor = "";
    public static HashMap<String, String> lookUpMap = new HashMap<String, String>();    // PORT - HASH
    public static TreeMap<String, String> sortedLookUpMap = new TreeMap<String, String>();    // HASH - PORT
    public static ArrayList<String> portNumbers = new ArrayList<String>();
    public static PriorityQueue<String> queue = new PriorityQueue<String>();
    public static String zeroAVD = "5554";
    public static String zeroAVDSocketId = "11108";
    public static final String LDUMP = "@";
    public static final String GDUMP = "*";
    public static final String QUERY = "QUERY";
    public static final String DELETE = "DELETE";

    public static final String GDUMP_QUERY = "GLOBALQUERY";
    public static final String GDUMP_QUERY_ANSWER = "GLOBAL_QUERY_ANSWER";

    public static final String NODE_JOIN = "NODE_JOIN";
    public static final String INSERT = "INSERT";
    public static final String QUERY_ANSWER = "QUERY_ANSWER";
    public static final String BROADCAST = "BROADCAST";

    public static final String GDUMP_DELETE = "GLOBALDELETE";

    private static final String KEY_FIELD = "key";
    private static final String VALUE_FIELD = "value";

    public static int globalQueryResultReceived = 0;    // Variable which keeps map of how many AVD's have sent the result of QUERY_ALL message

    public static HashMap<String, String> keyValuePairs = new HashMap<String, String>();

    public static Cursor cursor = null;

    public static String queryGeneratedFrom = null;

    public static boolean waitTillQueryResult = false;
    public static boolean thisIsAnotherAVDSQuery = false;

    private ContentResolver mContentResolver;
    public static Context currentContext;
    private Uri mUri;

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub

        String[] columnNames = {"key", "value"};
        Log.i("DELETE_FOR_KEY", selection);
        cursor = new MatrixCursor(columnNames);

        String selfPortHash = null;
        try {
            selfPortHash = genHash(myPortId);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if ((selfPortHash.equals(successor) && selfPortHash.equals(predessor) || (predessor.equals("") && successor.equals("")))) {
            // For single AVD, it doesnt matter
            Log.i("Single_AVD_DELETE", selection);
            if(selection.equals(LDUMP) || selection.equals(GDUMP)) {
                //return getAllDataFromLocal(uri);
                deleteAllDataFromLocal(uri);
            }
            else {
                Log.i("DELETE-LOCAL-KEY", selection);
                deleteFileFromLocal(uri, selection);
            }
        }
        else if(selection.equals(LDUMP)){
            deleteAllDataFromLocal(uri);
        }
        else if(selection.equals(GDUMP)){
            Log.i("DELETE-GDUMP", "Delete all the messages stored in DHT");
            deleteAllDataFromLocal(uri);    // First delete local
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, GDUMP_DELETE, myPortId);
        }
        else {
            String keyToFind = selection;
            String where = whereCanInsert(keyToFind);
            if(where.equals("PREDESSOR")){
                // Send message to Predessor
                Log.i("DELETE-PREDESSOR-SEARCH", keyToFind +"  " + sortedLookUpMap.get(predessor));
                sendDeleteQuery(keyToFind, myPortId, predessor);
            }
            else if(where.equals("SUCCESSOR")){
                // Send message to Successor
                Log.i("DELETE-SUCCESSOR-SEARCH", keyToFind +"  " + sortedLookUpMap.get(successor));
                sendDeleteQuery(keyToFind, myPortId, successor);
            }
            else if(where.equals("SELF")){
                deleteFileFromLocal(uri, selection);
            }
        }

        return 0;
    }

    private void sendDeleteQuery(String keyToFind, String myPortId, String target) {
        String msg = DELETE;
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, sortedLookUpMap.get(target), keyToFind, myPortId);

    }

    private void deleteAllDataFromLocal(Uri uri) {
        File fileDirectory = currentContext.getFilesDir();
        File[] listOfFiles = fileDirectory.listFiles();

        for (int i = 0; i < listOfFiles.length; i++) {
            File currentFile = listOfFiles[i];
            currentFile.delete();
        }
    }

    private void deleteFileFromLocal(Uri uri, String key) {
        File fileDirectory = currentContext.getFilesDir();
        File[] listOfFiles = fileDirectory.listFiles();

        for (int i = 0; i < listOfFiles.length; i++) {
            File currentFile = listOfFiles[i];
            if(currentFile.getName().equals(key)) {
                currentFile.delete();
                break;
            }
        }
    }


    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        String key = (String)values.get("key");
        String value = (String) values.get("value");

        Log.i("Insert_Query_Fired", key);

        String whereToInsert = whereCanInsert(key);

        if(whereToInsert.equals("SELF")) {
            return insertInLocalDb(uri, key, value);
        }
        else if(whereToInsert.equals("SUCCESSOR")) {
            String msg = INSERT;
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(successor));
        }
        return null;
    }

    private String whereCanInsert(String key) {
        try {
            String hashOfKey = genHash(key);
            String selfPortHash = genHash(myPortId);
            Log.i("KEY_HASH_VALUES", "key:  "+key+"  hashOfKey:  "+hashOfKey);
            String predessorC = "PREDESSOR", successorC = "SUCCESSOR", own = "SELF";

            // Suppose only one AVD is there in DHT
            if ((selfPortHash.equals(successor) && selfPortHash.equals(predessor) || (predessor.equals("") && successor.equals("")))) {
                return own;
            }

            // Middle Node
            if (predessor.compareTo(selfPortHash)<0 && selfPortHash.compareTo(successor)<0){
                Log.i("MIDDLE_NODE_CONDITION", " Middle Node");
                    if(hashOfKey.compareTo(selfPortHash)<=0 && hashOfKey.compareTo(predessor)>0){
                    return own;
                }
                else {
                    // Ask Successor
                    return successorC;
                }
            }
            else if(predessor.equals(successor)){
                // For 2 AVD Condition
                Log.i("Two_Node_Conditions", "For 2 Nodes Only");
                if(predessor.compareTo(selfPortHash)>0){
                    // For first Node
                    if(selfPortHash.compareTo(hashOfKey)>=0 || predessor.compareTo(hashOfKey)<0)
                        return own;
                    else
                    {
                        return successorC;
                    }
                }
                else {
                    // For Last Node
                    if(selfPortHash.compareTo(hashOfKey)>0 && hashOfKey.compareTo(predessor)>0){
                        return own;
                    }
                    else{
                        return successorC;
                    }
                }

            }
            else if(predessor.compareTo(selfPortHash)>0) {      // For First Node Of DHT
                Log.i("FIRST_NODE_CONDITION", " FIRST Node");
                if(hashOfKey.compareTo(selfPortHash)<=0 || hashOfKey.compareTo(predessor)>0){
                    return own;
                }

                else {
                    // ASK Successor TO Take Care
                    return successorC;
                }
            }
            else if(selfPortHash.compareTo(successor)>0){   // For LAST NODE IN DHT
                Log.i("LAST_NODE_CONDITION", " LAST Node");
                if(hashOfKey.compareTo(selfPortHash)<=0 && predessor.compareTo(hashOfKey)<0){
                    // Insert in local
                    return own;
                }

                else {
                    // ASK SUCCESSOR
                    return successorC;
                }
            }
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }


    public Uri insertInLocalDb(Uri uri, String key, String value) {
        String filename = key;
        String fileContents = value;
        FileOutputStream outputStream;

        String fileHashValue = "";
        try {
            fileHashValue = genHash(filename);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        try {
            Log.i("CREATE_FILE", filename+"   "+ fileContents +"  sha: " + fileHashValue);
            outputStream = currentContext.openFileOutput(filename, Context.MODE_PRIVATE);
            synchronized (outputStream){
                outputStream.write(fileContents.getBytes());
                outputStream.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        Log.v("insert", key +" : " + value );
        return uri;
    }

    @Override
    public boolean onCreate() {
        // TODO Auto-generated method stub

        //initialiseNodeIds();
        currentContext = this.getContext();


        mContentResolver = currentContext.getContentResolver();

        mUri = buildUri("content", "edu.buffalo.cse.cse486586.simpledht.provider");

        TelephonyManager tel = (TelephonyManager) currentContext.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String portNumber = String.valueOf((Integer.parseInt(portStr) * 2));

        Log.i("BOOT_UP", portNumber);
        // If current port is zeroAVD add it in its lookUpMap
        myPortId = portStr;         // Ex: 5554
        mySocketId = portNumber;    // Ex: 11108
        if (myPortId.equals(zeroAVD)) {
            try {
                Log.i("SEND_AWAKE_SIGNAL", myPortId);
                String hash = genHash(zeroAVD);
                lookUpMap.put(myPortId, hash);
                sortedLookUpMap.put(hash, mySocketId);
                if(!queue.contains(hash)){
                    queue.offer(hash);
                }
                if(!portNumbers.contains(hash)){
                    portNumbers.add(hash);
                    Collections.sort(portNumbers);
                }
                updateSuccessorsAndPredessors();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }


        try {
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);
            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            Log.e(TAG, "Can't create a ServerSocket");
        }

        // If AVD is not 0, then send message to the AVD 0 indicating the arrival of new AVD join
        if(!myPortId.equals(zeroAVD)){
            String msg = NODE_JOIN;
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, myPortId);
        }
        return false;
    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        //Cursor cursor = null;

        // TODO Auto-generated method stub
        String[] columnNames = {"key", "value"};
        Log.i("QUERY_FOR_KEY", selection);
        cursor = new MatrixCursor(columnNames);

        String selfPortHash = null;
        try {
            selfPortHash = genHash(myPortId);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // First handle for only one AVD
        // Here also check predessor.equals("") && successor.equals("") because for 1st mark
        // any random avd is chosen for local operations.
        // And since AVD 0 handles the join operation, these would be set to
        // blank as, node_join req never goes to the AVD 0
        if ((selfPortHash.equals(successor) && selfPortHash.equals(predessor) || (predessor.equals("") && successor.equals("")))) {
            // For single AVD, it doesnt matter
            Log.i("Single_AVD_QUERY", selection);
            if(selection.equals(LDUMP) || selection.equals(GDUMP)) {
                return getAllDataFromLocal(uri);
            }
            else {
                Log.i("QUERY-LOCAL-SEARCH", selection);
                cursor = findInLocal(selection);
                if(cursor != null){
                    return cursor;
                }
            }
        }
        else if(selection.equals(LDUMP)){
            Log.i("LOCAL_DUMP", "Querying Local Dump");
            return getAllDataFromLocal(uri);
        }
        else if(selection.equals(GDUMP)){
            // Get all the messages stored in entire DHT
            Log.i("QUERY-GDUMP", "Get all the messages stored in DHT");
            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, GDUMP_QUERY, mySocketId);
            Log.i("Wait_Start", "globalQueryResultReceived:: " + globalQueryResultReceived);
            while(globalQueryResultReceived != portNumbers.size()) {
                // wait here
            }
            Log.i("Wait_Over", "globalQueryResultReceived:: " + globalQueryResultReceived);
            globalQueryResultReceived = 0;
            return cursor;

        }
        else {
            String keyToFind = selection;
            String where = whereCanInsert(keyToFind);
            if(where.equals("PREDESSOR")){
                // Send message to Predessor
                Log.i("QUERY-PREDESSOR-SEARCH", keyToFind +"  " + sortedLookUpMap.get(predessor));
                sendQuery(keyToFind, mySocketId, predessor);

            }
            else if(where.equals("SUCCESSOR")){
                // Send message to Successor
                Log.i("QUERY-SUCCESSOR-SEARCH", keyToFind +"  " + sortedLookUpMap.get(successor));
                sendQuery(keyToFind, mySocketId, successor);
            }
            else if(where.equals("SELF")){
                Log.i("QUERY-LOCAL-SEARCH", keyToFind);
                cursor = findInLocal(keyToFind);
                if(cursor != null){
                    return cursor;
                }
            }
        }
        Log.i("Return_Cursor", "Returning Cursor From query Method");
        return cursor;
    }

    private Cursor getAllDataFromLocal(Uri uri) {
        File fileDirectory = currentContext.getFilesDir();
        File[] listOfFiles = fileDirectory.listFiles();
        String[] columnNames = {"key", "value"};
        MatrixCursor cursor = new MatrixCursor(columnNames);
        try {
            for (int i = 0; i < listOfFiles.length; i++) {
                File currentFile = listOfFiles[i];
                FileInputStream fileReaderStream = currentContext.openFileInput(currentFile.getName());
                InputStreamReader inputStream = new InputStreamReader(fileReaderStream);
                BufferedReader br = new BufferedReader(inputStream);
                String messageReceived = br.readLine();
                Log.v("File Content: ", messageReceived);
                String[] columnValues = {currentFile.getName(), messageReceived};
                cursor.addRow(columnValues);
            }
        }
        catch (Exception e){
            Log.e("Exception", "Exception in reading all local files");
            System.out.println(e.getStackTrace());
        }
        return cursor;
    }

    private void sendQuery(String keyToFind, String myPortId, String target) {

        String msg = QUERY;

        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, sortedLookUpMap.get(target), keyToFind, myPortId);

        Log.i("Boolean_Values_Before", "thisIsAnotherAVDSQuery:: "+ thisIsAnotherAVDSQuery +"   waitTillQueryResult:" + waitTillQueryResult);
        if(!thisIsAnotherAVDSQuery) {
            while (!waitTillQueryResult) {

            }
        }
        Log.i("Boolean_Values_After", "thisIsAnotherAVDSQuery:: "+ thisIsAnotherAVDSQuery +"   waitTillQueryResult:" + waitTillQueryResult);
        thisIsAnotherAVDSQuery = false;
        waitTillQueryResult = false;
    }

    private Cursor findInLocal(String keyToFind) {

        // Make these False, as the values reside in Local
        thisIsAnotherAVDSQuery = false;
        waitTillQueryResult = false;
        try{
            Log.v("query", keyToFind);
            FileInputStream fileReaderStream = currentContext.openFileInput(keyToFind);
            InputStreamReader inputStream = new InputStreamReader(fileReaderStream);
            BufferedReader br = new BufferedReader(inputStream);
            String messageReceived = br.readLine();
            Log.v("File Content: ", messageReceived);
            String[] columnNames = {"key", "value"};
            MatrixCursor cursor = new MatrixCursor(columnNames);
            String[] columnValues = {keyToFind, messageReceived};
            cursor.addRow(columnValues);

            // Check whether the request was generated from anotherAVD
            if(queryGeneratedFrom != null ){
            // Ask client to send the cursor as QUERY_ANSWER
                String msg = QUERY_ANSWER;
                String value = messageReceived;
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, queryGeneratedFrom, keyToFind, mySocketId, value);
                queryGeneratedFrom = null;
            }


            return cursor;
        }
        catch (Exception e) {
            Log.v("Exception", e.getMessage());
        }
        return null;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub

        return 0;
    }

    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    private Uri buildUri(String scheme, String authority) {
        Uri.Builder uriBuilder = new Uri.Builder();
        uriBuilder.authority(authority);
        uriBuilder.scheme(scheme);
        return uriBuilder.build();
    }

    private String[] getAllConnectedClients() {
        int i=0;
        String []clients = new String[lookUpMap.size()];
        for(String key : lookUpMap.keySet()){
            clients[i++] = key;
        }
        return clients;
    }

    private String[] getAllConnectedClientsSocketIds() {
        int i=0;
        String []clients = new String[lookUpMap.size()];
        for(String key : lookUpMap.keySet()){
            clients[i++] = String.valueOf(Integer.valueOf(key)*2);
        }
        return clients;
    }

    private void updateLookUpMap(String clients){
        String[] clientList = clients.split(",");
        for(String client : clientList) {
            if(!lookUpMap.containsKey(client)) {
                try {
                    String hash = genHash(client);
                    lookUpMap.put(client, hash);
                    sortedLookUpMap.put(hash,  String.valueOf(Integer.parseInt(client) * 2));
                    if(!queue.contains(hash)) {
                        queue.offer(hash);
                    }
                    if(!portNumbers.contains(hash)){
                        portNumbers.add(hash);
                        Collections.sort(portNumbers);
                    }
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void updateSuccessorsAndPredessors(){
        String prev ="", next="";
        String myPortHash = "";

        boolean found = false;

        try {
            myPortHash = genHash(myPortId);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Print portNumbers as they are in sorted order
        String order = "";
        for(String p : portNumbers){
            order += p + "  ";
        }

        //Log.i("SORT_ORDER::  " , order);

        int index = portNumbers.indexOf(myPortHash);
        int prevIndex = (index + portNumbers.size() - 1) % portNumbers.size();
        int nextIndex = (index+1) % portNumbers.size();

        predessor = portNumbers.get(prevIndex);
        successor = portNumbers.get(nextIndex);

        Log.i("MY_INFO", "My Port:  " + myPortId +"  MyPort Hash: " + myPortHash + "  Predessor Hash:  " + predessor + "  Successor Hash:  " + successor);

    }

    private class ServerTask extends AsyncTask<ServerSocket, String, Void> {

        SimpleDhtProvider DHT;

        @Override
        protected Void doInBackground(ServerSocket... sockets) {
            ServerSocket serverSocket = sockets[0];
            DHT = new SimpleDhtProvider();

            /*
             * TODO: Fill in your server code that receives messages and passes them
             * to onProgressUpdate().
             */
            Socket socket = null;
            DataInputStream dis = null;
            DataOutputStream dos = null;
            InputStream stream = null;

            while (true) {
                try {
                    socket = serverSocket.accept();
                    stream = socket.getInputStream();

                    InputStreamReader inputStream = new InputStreamReader(stream);
                    dis = new DataInputStream(stream);
                    //BufferedReader br = new BufferedReader(inputStream);
                    String messageReceived = "";
                    String message = dis.readUTF();
                    messageReceived = message;

                    String[] splittedMessage = messageReceived.split(";");

                    String messageType = splittedMessage[0].split(":")[1];

                    if (messageType.equals(NODE_JOIN)) {
                        Log.i("UPDATE_LOOK_UP_MAP", splittedMessage[1]);
                        String clientPortNumber = splittedMessage[1].split(":")[1];
                        try {
                            String hash = DHT.genHash(clientPortNumber);
                            lookUpMap.put(clientPortNumber, hash);
                            sortedLookUpMap.put(hash, String.valueOf(Integer.parseInt(clientPortNumber)*2));
                            if (!queue.contains(hash)) {
                                queue.offer(hash);
                            }
                            if (!portNumbers.contains(hash)) {
                                portNumbers.add(hash);
                                Collections.sort(portNumbers);
                            }
                            DHT.updateSuccessorsAndPredessors();
                            Log.i("LOOKUP_TABLE_UPDATED", "YES");
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                        // Now broadcast the lookupMap to all the connected AVDs

                        String[] connectedClients = DHT.getAllConnectedClients();
                        Message broadCastMessage = new Message(BROADCAST);
                        broadCastMessage.setConnectedClients(connectedClients);

                        String[] connectedClientsSockets = DHT.getAllConnectedClientsSocketIds();
                        OutputStream outputStream = null;

                        for (String client : connectedClientsSockets) {
                            Socket newSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(client));
                            newSocket.setTcpNoDelay(true);
                            newSocket.setSoTimeout(1000);
                            outputStream = newSocket.getOutputStream();
                            OutputStreamWriter out = new OutputStreamWriter(outputStream,
                                    "UTF-8");

                            Log.i("SENDING_BROADCAST_MSG", "Sending to: " + client + " " + broadCastMessage.getString());

                            dos = new DataOutputStream(outputStream);
                            dos.writeUTF(broadCastMessage.getString());
                            outputStream.close();
                            dos.close();
                            newSocket.close();
                        }

                    } else if (messageType.equals(BROADCAST)) {
                        Log.i("RECEIVED_BROADCAST_MSG", splittedMessage[1].split(":")[1]);
                        DHT.updateLookUpMap(splittedMessage[1].split(":")[1]);
                        DHT.updateSuccessorsAndPredessors();
                    } else if (messageType.equals(INSERT)) {
                        Log.i("INSERT_REQUEST", splittedMessage[1].split(":")[1]);
                        String key = splittedMessage[1].split(":")[1];
                        String value = splittedMessage[2].split(":")[1];
//
                        String whereToInsert = DHT.whereCanInsert(key);
                        if(whereToInsert == null){
                            Log.i("whereToInsert", "null");
                        }
                        Log.i("whereToInsert", whereToInsert);
                        if(whereToInsert.equals("SELF")){
                            Log.i("INSERT_IN_LOCALDB", key + " : " + value);
                            DHT.insertInLocalDb(mUri, key, value);
                        }
                        else if(whereToInsert.equals("SUCCESSOR")){
                            Log.i("ASKING_PREDSR_TO_INSERT", key+" : " + value);
                            askSuccessorToInsertMessage(key, value);
                        }
                    }
                    else if(messageType.equals(QUERY)) {
                        thisIsAnotherAVDSQuery = true;
                        Log.i("QUERY_SERVER", splittedMessage[1]);
                        String keyToSearch = splittedMessage[2].split(":")[1];
                        queryGeneratedFrom = splittedMessage[3].split(":")[1];
                        DHT.query(mUri, null, keyToSearch, null, null);
                    }
                    else if(messageType.equals(QUERY_ANSWER)) {
                        String keyToSearch = splittedMessage[1].split(":")[1];
                        Log.i(QUERY_ANSWER, splittedMessage[2]);
                        String value = splittedMessage[2].split(":")[1];
                        String[] columnNames = {"key", "value"};
                        MatrixCursor cursor1 = new MatrixCursor(columnNames);
                        String[] columnValues = {keyToSearch, value};
                        cursor1.addRow(columnValues);
                        cursor = cursor1;
                        waitTillQueryResult = true;
                        thisIsAnotherAVDSQuery = false;

                    }
                    else if(messageType.equals(GDUMP_QUERY)) {
                        String queryPort = splittedMessage[1].split(":")[1];
                        if(!queryPort.equals(myPortId)){
                            Cursor cursor1 = DHT.getAllDataFromLocal(mUri);
                            int keyIndex = cursor1.getColumnIndex(KEY_FIELD);
                            int valueIndex = cursor1.getColumnIndex(VALUE_FIELD);

                            Message responseMessage = new Message(GDUMP_QUERY_ANSWER);
                            responseMessage.setQueryPort(queryPort);
                            StringBuilder sb = new StringBuilder();

                            while(cursor1.moveToNext()) {
                                sb.append(cursor1.getString(keyIndex));
                                sb.append(" ");
                                sb.append(cursor1.getString(valueIndex));
                                sb.append(",");
                                // key value,key value,key value
                            }
                            Log.i("GDUMP_QUERY_Response", responseMessage.getString());
                            responseMessage.setGDUMP_Response(sb.toString());
                            DHT.sendGlobalMessageResponse(responseMessage);
                            DHT.ForwardGlobalMessageToSUccessor(queryPort);
                            Log.i("GDUMP_QUERY_Res_Sent", responseMessage.getString());
                        }

                    }
                    else if(messageType.equals(GDUMP_QUERY_ANSWER)) {
                        // Write this method
                        // Combine everyones anser and also call to getAllDataFromLocal to get its own keys and
                        // then return the result
                        String[] columnNames = {"key", "value"};

                        Log.i("Data_Received::", String.valueOf(splittedMessage.length));
                        globalQueryResultReceived++;
                        if(splittedMessage.length>2 && splittedMessage[2].length()>0 && splittedMessage[2].indexOf(":")>=0) {
                            String []responseString = splittedMessage[2].split(":");
                            if(responseString.length>=2) {
                                String data = responseString[1];

                                Log.i("GDMP_QUERY_ANSWER", "globalQueryResultReceived:: " + globalQueryResultReceived + " PORTs:" + portNumbers.size());
                                getKeyValuePairs(data);
                            }
                        }

                        if(globalQueryResultReceived == portNumbers.size()-1) {
                            //globalQueryResultReceived = 0;
                            // Get All Data Of Current AVD
                            Log.i("Match", "globalQueryResultReceived == portNumbers.size()-1");
                            Cursor cursor1 = DHT.getAllDataFromLocal(mUri);
                            MatrixCursor mCursor = new MatrixCursor(columnNames);

                            for(String key : keyValuePairs.keySet()) {
                                String[] columnValues = {key, keyValuePairs.get(key)};
                                mCursor.addRow(columnValues);
                            }
                            // Now Merge the cursor and MatrixCursor
                            MergeCursor mergeCursor = new MergeCursor(new Cursor[] { mCursor, cursor1 });
                            Log.i("SettingMergeCursor", "Set MergeCursor");
                            cursor = mergeCursor;   // Set main cursor of SIMPLEDHT to this mergedCursor

                            globalQueryResultReceived++; // Now again increase here, so the while loop breaks
                        }

                    }
                    else if(messageType.equals(DELETE)) {
                        Log.i("DELETE_SERVER", splittedMessage[1]);
                        String keyToSearch = splittedMessage[2].split(":")[1];
                        //queryGeneratedFrom = splittedMessage[3].split(":")[1];
                        DHT.delete(mUri,keyToSearch, null);
                    }
                    else if(message.equals(GDUMP_DELETE)) {
                        Log.i("DELETE_SERVER_ALL", "Delete all messages from local");
                        String queryPortId = splittedMessage[1].split(":")[1];

                        DHT.deleteAllDataFromLocal(mUri);
                        Log.i("PORT_IDS", "MyPortId::"+myPortId+"  QueryPort: "+ queryPortId);
                        if(!queryPortId.equals(myPortId)){
                            // ASk my successor to delete their all queries
                            DHT.askSuccessorToDeleteItsOwnRecords();
                        }
                    }

                } catch (IOException e) {
                    Log.i("Server_Failed", "YE");
                    Log.e(TAG, "Client Disconnected");
                } catch (Exception e) {
                    e.printStackTrace();
                    Log.e(TAG, "Failed to accept connection");
                }
                finally {
                    try {
                        if (socket != null)
                            socket.close();

                    } catch (IOException e) {
                        Log.e(TAG, "Error while disconnecting socket");
                    }
                }
            }
        }

        private void askSuccessorToInsertMessage(String key, String value) {

            Socket newSocket = null;
            OutputStream outputStream = null;
            DataOutputStream dos = null;
            InputStream stream = null;

            String successorPort = sortedLookUpMap.get(successor);
            Message message = new Message(INSERT);
            message.setKey(key);
            message.setValue(value);
            try {
                newSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(successorPort));
                newSocket.setTcpNoDelay(true);
                newSocket.setSoTimeout(1000);
                outputStream = newSocket.getOutputStream();
                OutputStreamWriter out = new OutputStreamWriter(outputStream,
                        "UTF-8");

                Log.i("SENDING_INSERT_MSG", "Sending to: " + successorPort + " " + message.getString());

                dos = new DataOutputStream(outputStream);
                dos.writeUTF(message.getString());
                outputStream.close();
                dos.close();
                newSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (outputStream != null)
                        outputStream.close();
                    if (dos != null)
                        dos.close();
                    if (newSocket != null)
                        newSocket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    private void ForwardGlobalMessageToSUccessor(String queryPort) {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, GDUMP_QUERY, mySocketId, queryPort);
    }

    private void askSuccessorToDeleteItsOwnRecords() {
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, GDUMP_DELETE, myPortId);
    }

    private void sendGlobalMessageResponse(Message responseMessage) {

        String msg = GDUMP_QUERY_ANSWER;
        String client = responseMessage.getQueryPort();
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, client, responseMessage.getString());
//        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, sortedLookUpMap.get(target), keyToFind, myPortId);
    }

    private void getKeyValuePairs(String data) {
        // key value,key value,key value
        String[] pairs = data.split(",");
        for(String pair : pairs) {
            String key = pair.split(" ")[0];
            String value = pair.split(" ")[1];
            if(key.length()>0 && value.length()>0){
                keyValuePairs.put(key, value);
            }
        }
    }


    private class ClientTask extends AsyncTask<String, Void, Void> {

        @Override
        protected Void doInBackground(String... msgs) {
            String order = msgs[0];

            Socket socket = null;
            OutputStream stream = null;
            DataOutputStream dos = null;
            DataInputStream dis = null;

            try {
                if (order.equals(NODE_JOIN)) {
                    String portNumber = msgs[1];
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(zeroAVDSocketId));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    Message message = new Message(NODE_JOIN);
                    message.setClient(portNumber);

                    Log.i("Sending_node_join_req","Sending_node_join_req");
                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                }
                else if(order.equals(INSERT)) {
                    Log.i("CLIENT_INSERT", "ORDER");
                    Log.i("CLIENT_INSERT", msgs[1]);
                    Log.i("CLIENT_INSERT", msgs[2]);
                    Log.i("CLIENT_INSERT", msgs[3]);

                    String client = msgs[3];
                    String key = msgs[1];
                    String value = msgs[2];
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(client));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);
                    Message message = new Message(INSERT);
                    message.setKey(key);
                    message.setValue(value);

                    Log.i("Sending_Key_Insert",key +"  :  " + value +":: to: "+client);
                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                }
                else if(order.equals(QUERY)) {
                    String target = msgs[1];
                    String keyToFind = msgs[2];
                    String myPortId = msgs[3];

                    Message message = new Message(QUERY);
                    message.setAssociatedPort(myPortId);
                    message.setKeyToSearch(keyToFind);


                    if(queryGeneratedFrom != null) {
                        message.setQueryPort(queryGeneratedFrom);
                        queryGeneratedFrom = null;
                    }
                    else {
                        message.setQueryPort(myPortId);
                    }
                    Log.i("SEND_QUERY_MSG", msgs[1]);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(target));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();

                }
                else if(order.equals(QUERY_ANSWER)) {
                    Message message = new Message(QUERY_ANSWER);

                    Log.i("SEND_QUERY_MSG_ANSWER", msgs[1]);

                    String target = msgs[1];
                    String keyToFind = msgs[2];
                    String value = msgs[4];

                    message.setKeyToSearch(keyToFind);
                    message.setQueryAnswer(value);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(target));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();

                }
                else if(order.equals(GDUMP_QUERY)) {
                    Message message =  new Message(GDUMP_QUERY);
                    String queryPort;


                    String currentPort = msgs[1]; // SocketId
                    message.setCurrentPort(currentPort);


                    if(msgs.length>2) {
                        // Means forward message, as the GDUMP is issued by diff AVD, so that AVD's port Id should be there
                        // in the message
                        queryPort = msgs[2];
                        message.setQueryPort(queryPort);
                    }
                    else {
                        // current port is the query port, means this AVD has issued GDUMP
                        queryPort = currentPort;
                        message.setQueryPort(queryPort);
                    }

                    Log.i("SEND_GLOBAL_QUERY_MSG", msgs[1]);


                    String successorSocketId = sortedLookUpMap.get(successor);

                    Log.i("Port_info", "MyPOrt : " + mySocketId + " MySuccessor: " + successorSocketId);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successorSocketId));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                    Log.i("Global_Message_Sent", successorSocketId);


                }
                else if(order.equals(GDUMP_QUERY_ANSWER)) {
                    String target = msgs[1];
                    String responseMessage = msgs[2];
                    Log.i("Send_Global_Response", "Sending Global Response To :  " + target);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(target));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(responseMessage);

                    stream.flush();
                    out.flush();
                }
                else if(order.equals(DELETE)) {
                    String target = msgs[1];
                    String keyToFind = msgs[2];
                    String myPortId = msgs[3];

                    Message message = new Message(DELETE);
                    message.setAssociatedPort(myPortId);
                    message.setKeyToSearch(keyToFind);


                    Log.i("SEND_DELETE_MSG", msgs[1]);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(target)*2);
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);

                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                }
                else if(order.equals(GDUMP_DELETE)) {
                    Message message =  new Message(GDUMP_DELETE);
                    String queryPort = msgs[1];
                    message.setQueryPort(queryPort);
                    Log.i("SEND_GLOBAL_DELETE_MSG", msgs[1]);

                    // sortedLookUp Hash-SocketID
                    //LOokup portId - Hash

                    String successorSocketId = sortedLookUpMap.get(successor);
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(successorSocketId));
                    socket.setTcpNoDelay(true);
                    socket.setSoTimeout(1000);
                    Log.i("SUCCESSOR_DELETE", "Send Message To "+ successorSocketId);
                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                }
            }
            catch (UnknownHostException unknownHost){
                Log.i("Unknown_host", "Unknown_host");
            }
            catch (IOException io){
                System.out.println(io.getStackTrace());
            }
            finally {
                try{
                    if(stream != null)
                        stream.close();
                    if(dis != null)
                        dis.close();
                    if(dos!=null)
                        dos.close();
                    if(socket != null)
                        socket.close();
                }
                catch (IOException e){
                    Log.e(TAG, "Error while disconnecting socket");
                }
            }
            return null;
        }
    }
}
