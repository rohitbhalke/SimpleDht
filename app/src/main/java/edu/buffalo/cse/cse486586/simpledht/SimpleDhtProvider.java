package edu.buffalo.cse.cse486586.simpledht;

import android.app.Activity;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Bundle;
import android.telephony.TelephonyManager;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.text.method.ScrollingMovementMethod;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Formatter;
import java.util.HashMap;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.DataInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.PriorityQueue;
import java.util.Random;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.TreeMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.PriorityBlockingQueue;


import android.content.ContentProvider;
import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.telephony.TelephonyManager;
import android.util.Log;

public class SimpleDhtProvider extends ContentProvider {

    static final String TAG = SimpleDhtProvider.class.getSimpleName();

    static String[] REMOTE_PORTS = {"11108", "11112", "11116", "11120", "11124"};
    static final int SERVER_PORT = 10000;
    HashMap<String, String> map = new HashMap<String, String>();
    public static String myPortId = "";
    public static String predessor = "";
    public static String successor = "";
    public static HashMap<String, String> lookUpMap = new HashMap<String, String>();    // PORT - HASH
    public static TreeMap<String, String> sortedLookUpMap = new TreeMap<String, String>();    // HASH - PORT
    public static ArrayList<String> portNumbers = new ArrayList<String>();
    public static PriorityQueue<String> queue = new PriorityQueue<String>();
    public static String zeroAVD = "11108";
    public static final String LDUMP = "@";
    public static final String GDUMP = "*";
    public static final String QUERY = "QUERY";

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
        return 0;
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

//        try {
//            String hashOfKey = genHash(key);
//            String selfPortHash = genHash(myPortId);
//
//            // Suppose only one AVD is there in DHT
//            if(selfPortHash.equals(successor) && selfPortHash.equals(predessor)) {
//                return insertInLocalDb(uri, key, value);
//            }
//
////            if(selfPortHash.compareTo(hashOfKey)>=0 && successor.compareTo(hashOfKey)>=0)
////                return insertInLocalDb(uri, key, value);
//
//            /*
//                If AVD is first avd in DHT, and hashkey is less than its hash value
//             */
//            if(selfPortHash.compareTo(hashOfKey)>=0 && predessor.compareTo(hashOfKey)>0)
//            {
//                return insertInLocalDb(uri, key, value);
//            }
//
//            // if key's hash value is in between successor value and selfHashValue
//            if(hashOfKey.compareTo(successor)<0 && hashOfKey.compareTo(selfPortHash)>=0){
//                return insertInLocalDb(uri, key, value);
//            }
//
//            /* if currentport is last port from the DHT then check
//                if hashOfKey is greater than currentPortHash and currentPortHash is less than successorPorthash
//                then insert into this lastAVD in the DHT
//             */
//
//            if(hashOfKey.compareTo(selfPortHash)>=0 && selfPortHash.compareTo(successor)>0) {
//                return insertInLocalDb(uri, key, value);
//            }
//
//            Log.i("STATISTICS", key +"   "+ String.valueOf(hashOfKey.compareTo(successor))+"  "+
//                    String.valueOf(hashOfKey.compareTo(selfPortHash)>=0) +
//                    String.valueOf(hashOfKey.compareTo(selfPortHash)>=0) +
//                    String.valueOf(selfPortHash.compareTo(successor)>0));
//
//            // Else go to successor
//            Log.i("ASKING_SUCER_TO_INSERT", key+" : " + value);
//            String msg = "INSERT";
//            new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(successor));
//
//
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }

        // New Logic
        try {
            String hashOfKey = genHash(key);
            String selfPortHash = genHash(myPortId);

            // Suppose only one AVD is there in DHT
            if (selfPortHash.equals(successor) && selfPortHash.equals(predessor)) {
                return insertInLocalDb(uri, key, value);
            }

            // Middle Node
            if (predessor.compareTo(selfPortHash)<0 && selfPortHash.compareTo(successor)<0){
                if(hashOfKey.compareTo(selfPortHash) < 0) {
                    // Ask Predessor
                    String msg = "INSERT";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(predessor));
                }
                else if(hashOfKey.compareTo(selfPortHash)>=0 && hashOfKey.compareTo(successor)<0){
                    return insertInLocalDb(uri, key, value);
                }
                else if(hashOfKey.compareTo(successor)>0){
                    // Ask Successor
                    String msg = "INSERT";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(successor));
                }
            }
            else if(predessor.compareTo(selfPortHash)>0) {      // For First Node Of DHT
                if(hashOfKey.compareTo(selfPortHash)<=0){
                    // ASK PREDESSOR TO TAKE CARE
//                    String msg = "INSERT";
//                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(predessor));
                    return insertInLocalDb(uri, key, value);
                }
                else if(hashOfKey.compareTo(selfPortHash)>=0 && hashOfKey.compareTo(successor)<0) {
                    // insert in local
                    return insertInLocalDb(uri, key, value);
                }
                else {
                    // ASK Successor TO Take Care
                    String msg = "INSERT";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(successor));
                }
            }
            else if(selfPortHash.compareTo(successor)>0){
                if(hashOfKey.compareTo(selfPortHash)>=0){
                    // Insert in local
                    return insertInLocalDb(uri, key, value);
                }
                else if(hashOfKey.compareTo(selfPortHash)<0){
                    // ASK PREDESSOR
                    String msg = "INSERT";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(predessor));
                }
                else {
                    // ASK SUCCESSOR
                    String msg = "INSERT";
                    new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg,key, value, sortedLookUpMap.get(successor));
                }
            }
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return null;
    }

    private boolean canInsertInLocalDB(String key) {
        try {
            String hashOfKey = genHash(key);
            String selfPortHash = genHash(myPortId);

            // Suppose only one AVD is there in DHT
            if (selfPortHash.equals(successor) && selfPortHash.equals(predessor)) {
                return true;
            }


            // if key's hash value is in between successor value and selfHashValue
            if (hashOfKey.compareTo(successor) < 0 && hashOfKey.compareTo(selfPortHash) >= 0) {
                return true;
            }

            if(selfPortHash.compareTo(hashOfKey)>=0 && predessor.compareTo(hashOfKey)>0){
                return true;
            }

            /* if currentport is last port from the DHT then check
                if hashOfKey is greater than currentPortHash and currentPortHash is less than successorPorthash
                then insert into this lastAVD in the DHT
             */

            if (hashOfKey.compareTo(selfPortHash) >= 0 && selfPortHash.compareTo(successor) > 0) {
                return true;
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    private String whereCanInsert(String key) {
        try {
            String hashOfKey = genHash(key);
            String selfPortHash = genHash(myPortId);
            Log.i("KEY_HASH_VALUES", "key:  "+key+"  hashOfKey:  "+hashOfKey);
            String predessorC = "PREDESSOR", successorC = "SUCCESSOR", own = "SELF";

            // Suppose only one AVD is there in DHT
            if (selfPortHash.equals(successor) && selfPortHash.equals(predessor)) {
                return own;
            }

            // Middle Node
            if (predessor.compareTo(selfPortHash)<0 && selfPortHash.compareTo(successor)<0){
                if(hashOfKey.compareTo(selfPortHash) < 0) {
                    // Ask Predessor
                    return predessorC;
                }
                else if(hashOfKey.compareTo(selfPortHash)>=0 && hashOfKey.compareTo(successor)<0){
                    return own;
                }
                else if(hashOfKey.compareTo(successor)>0){
                    // Ask Successor
                    return successorC;
                }
            }
            else if(predessor.compareTo(selfPortHash)>0) {      // For First Node Of DHT
//                if(hashOfKey.compareTo(predessor)>0) {
//                    // ASK PREDESSOR TO TAKE CARE
//                    return predessorC;
//                }
                if(hashOfKey.compareTo(selfPortHash)<=0){
                    return own;
                }
                //else if(hashOfKey.compareTo(selfPortHash)>=0 && hashOfKey.compareTo(successor)<0) {
                else if(hashOfKey.compareTo(selfPortHash)>=0 && hashOfKey.compareTo(successor)<0) {

                    // insert in local
                    return own;
                }
                else {
                    // ASK Successor TO Take Care
                    return successorC;
                }
            }
            else if(selfPortHash.compareTo(successor)>0){   // For LAST NODE IN DHT
                if(hashOfKey.compareTo(selfPortHash)>=0){
                    // Insert in local
                    return own;
                }
                //else if(hashOfKey.compareTo(predessor)>0 && hashOfKey.compareTo(selfPortHash)<0){
                else if(hashOfKey.compareTo(selfPortHash)<0){
                    // ASK PREDESSOR
                    return predessorC;
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

        try {
            Log.i("CREATE_FILE", filename+"   "+ fileContents);
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
        mUri = buildUri("content", "content://edu.buffalo.cse.cse486586.simpledht.provider");

        TelephonyManager tel = (TelephonyManager) currentContext.getSystemService(Context.TELEPHONY_SERVICE);
        String portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
        final String portNumber = String.valueOf((Integer.parseInt(portStr) * 2));

        Log.i("BOOT_UP", portNumber);
        // If current port is zeroAVD add it in its lookUpMap
        myPortId = portNumber;
        if (portNumber.equals(zeroAVD)) {
            try {
                Log.i("SEND_AWAKE_SIGNAL", myPortId);
                String hash = genHash(zeroAVD);
                lookUpMap.put(portNumber, hash);
                sortedLookUpMap.put(hash, portNumber);
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
            /*
             * Create a server socket as well as a thread (AsyncTask) that listens on the server
             * port.
             *
             * AsyncTask is a simplified thread construct that Android provides. Please make sure
             * you know how it works by reading
             * http://developer.android.com/reference/android/os/AsyncTask.html
             */
            ServerSocket serverSocket = new ServerSocket(SERVER_PORT);

            new ServerTask().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
        } catch (IOException e) {
            /*
             * Log is a good way to debug your code. LogCat prints out all the messages that
             * Log class writes.
             *
             * Please read http://developer.android.com/tools/debugging/debugging-projects.html
             * and http://developer.android.com/tools/debugging/debugging-log.html
             * for more information on debugging.
             */
            Log.e(TAG, "Can't create a ServerSocket");
        }

        // If AVD is not 0, then send message to the AVD 0 indicating the arrival of new AVD join
        if(!myPortId.equals(zeroAVD)){
            String msg = "NODE_JOIN";
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

        if(selection.equals(LDUMP)){

        }
        else if(selection.equals(GDUMP)){

        }
        else {
            String keyToFind = selection;
            String where = whereCanInsert(keyToFind);
            if(where.equals("PREDESSOR")){
                // Send message to Predessor
                Log.i("QUERY-PREDESSOR-SEARCH", keyToFind +"  " + sortedLookUpMap.get(predessor));
                sendQuery(keyToFind, myPortId, predessor);

            }
            else if(where.equals("SUCCESSOR")){
                // Send message to Successor
                Log.i("QUERY-SUCCESSOR-SEARCH", keyToFind +"  " + sortedLookUpMap.get(successor));
                sendQuery(keyToFind, myPortId, successor);
            }
            else if(where.equals("SELF")){
                Log.i("QUERY-LOCAL-SEARCH", keyToFind);
                cursor = findInLocal(keyToFind);
                if(cursor != null){
                    return cursor;
                }
            }
        }

        return cursor;
    }

    private void sendQuery(String keyToFind, String myPortId, String target) {

        String msg = QUERY;
        new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, sortedLookUpMap.get(target), keyToFind, myPortId);
        //while()
        /*
                    Things remainining
                    1) Now how do the query generator port know to wait for the Cursor to return from
                    ServerTask. ( Right now it is getting returned from Query method, we need a
                    machanism to stop execution here, till cursor is set from server task)

         */

        if(!thisIsAnotherAVDSQuery) {
            while (!waitTillQueryResult) {

            }
        }
        thisIsAnotherAVDSQuery = false;
        waitTillQueryResult = false;
    }

    private Cursor findInLocal(String keyToFind) {

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
                String msg = "QUERY_ANSWER";
                String value = messageReceived;
                new ClientTask().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, msg, queryGeneratedFrom, keyToFind, myPortId, value);
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

    private void updateLookUpMap(String clients){
        String[] clientList = clients.split(",");
        for(String client : clientList) {
            if(!lookUpMap.containsKey(client)) {
                try {
                    String hash = genHash(client);
                    lookUpMap.put(client, hash);
                    sortedLookUpMap.put(hash,  client);
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

        Log.i("SORT_ORDER::  " , order);

        int index = portNumbers.indexOf(myPortHash);
        int prevIndex = (index + portNumbers.size() - 1) % portNumbers.size();
        int nextIndex = (index+1) % portNumbers.size();

        predessor = portNumbers.get(prevIndex);
        successor = portNumbers.get(nextIndex);

        Log.i("MY_INFO", "My Port:  " + myPortId +"  MyPort Hash: " + myPortHash + "  Predessor Hash:  " + predessor + "  Successor Hash:  " + successor);

        /*ArrayList<String> al = new ArrayList<String>();

        while(!queue.isEmpty()) {
            String current = queue.poll();
            if(current.equals(myPortHash)){
                al.add(current);
                found = true;
                break;
            }
            prev = current;
            al.add(current);
        }

        if(found) {

            if(prev.length()==0){
                // set last value from the queue
                String val = "";
                while(!queue.isEmpty()){
                    val = queue.poll();
                }
                if(val.length()>0){
                    prev = val;
                }
                else {
                    prev = myPortHash;
                }
            }


            // now set next

        }*/



    }

    private void printLookUpMap(){
        String clients = "";
        for(String client : lookUpMap.keySet()) {
            clients += client + "  " + lookUpMap.get(client);
        }
        Log.i("LOOKUP_MAP", myPortId +"  " + clients +"  ");
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

                    if (messageType.equals("NODE_JOIN")) {
                        Log.i("UPDATE_LOOK_UP_MAP", splittedMessage[1]);
                        String clientPortNumber = splittedMessage[1].split(":")[1];
                        try {
                            String hash = DHT.genHash(clientPortNumber);
                            lookUpMap.put(clientPortNumber, hash);
                            sortedLookUpMap.put(hash, clientPortNumber);
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
                        Message broadCastMessage = new Message("BROADCAST");
                        broadCastMessage.setConnectedClients(connectedClients);

                        OutputStream outputStream = null;

                        for (String client : connectedClients) {
                            Socket newSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                                    Integer.parseInt(client));
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

                    } else if (messageType.equals("BROADCAST")) {
                        Log.i("RECEIVED_BROADCAST_MSG", splittedMessage[1].split(":")[1]);
                        DHT.updateLookUpMap(splittedMessage[1].split(":")[1]);
                        DHT.printLookUpMap();
                        DHT.updateSuccessorsAndPredessors();
                    } else if (messageType.equals("INSERT")) {
                        Log.i("INSERT_REQUEST", splittedMessage[1].split(":")[1]);
                        String key = splittedMessage[1].split(":")[1];
                        String value = splittedMessage[2].split(":")[1];
//                        if (DHT.canInsertInLocalDB(key)) {
//                            Log.i("INSERT_IN_LOCALDB", key + " : " + value);
//                            DHT.insertInLocalDb(mUri, key, value);
//                        } else {
//                            // Send message to Successor to insert this key
//                            Log.i("ASKING_SUCER_TO_INSERT", key+" : " + value);
//                            askSuccessorToInsertMessage(key, value);
//                        }
                        String whereToInsert = DHT.whereCanInsert(key);
                        if(whereToInsert.equals("SELF")){
                            Log.i("INSERT_IN_LOCALDB", key + " : " + value);
                            DHT.insertInLocalDb(mUri, key, value);
                        }
                        else if(whereToInsert.equals("PREDESSOR")){
                            Log.i("ASKING_PREDSR_TO_INSERT", key+" : " + value);
                            askPredessorInsertMessage(key, value);
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
                    else if(messageType.equals("QUERY_ANSWER")) {
                        String keyToSearch = splittedMessage[1].split(":")[1];
                        Log.i("QUERY_ANSWER", splittedMessage[2]);
                        String value = splittedMessage[2].split(":")[1];
                        String[] columnNames = {"key", "value"};
                        MatrixCursor cursor1 = new MatrixCursor(columnNames);
                        String[] columnValues = {keyToSearch, value};
                        cursor1.addRow(columnValues);
                        cursor = cursor1;
                        waitTillQueryResult = true;
                        thisIsAnotherAVDSQuery = false;

                    }

                } catch (IOException e) {
                    Log.i("Server_Failed", "YE");
                    Log.e(TAG, "Client Disconnected");
                }
                try {
                    if (stream != null)
                        stream.close();
                    if (dis != null)
                        dis.close();
                    if (dos != null)
                        dos.close();
                    if (socket != null)
                        socket.close();

                } catch (IOException e) {
                    Log.e(TAG, "Error while disconnecting socket");
                }
            }
        }

        private void askSuccessorToInsertMessage(String key, String value) {

            Socket newSocket = null;
            OutputStream outputStream = null;
            DataOutputStream dos = null;
            InputStream stream = null;

            String successorPort = sortedLookUpMap.get(successor);
            Message message = new Message("INSERT");
            message.setKey(key);
            message.setValue(value);
            try {
                newSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(successorPort));
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

        private void askPredessorInsertMessage(String key, String value) {

            Socket newSocket = null;
            OutputStream outputStream = null;
            DataOutputStream dos = null;
            InputStream stream = null;

            String successorPort = sortedLookUpMap.get(predessor);
            Message message = new Message("INSERT");
            message.setKey(key);
            message.setValue(value);
            try {
                newSocket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                        Integer.parseInt(successorPort));
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


    private class ClientTask extends AsyncTask<String, Void, Void> {

        //ArrayList<Message> proposedNumbers = new ArrayList<Message>();

        @Override
        protected Void doInBackground(String... msgs) {
            String order = msgs[0];

            Socket socket = null;
            OutputStream stream = null;
            DataOutputStream dos = null;
            DataInputStream dis = null;

            try {
                if (order.equals("NODE_JOIN")) {
                    String portNumber = msgs[1];
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(zeroAVD));
                    socket.setSoTimeout(3000);
                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    Message message = new Message("NODE_JOIN");
                    message.setClient(portNumber);

                    Log.i("Sending_node_join_req","Sending_node_join_req");
                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                }
                else if(order.equals("INSERT")) {
                    Log.i("CLIENT_INSERT", "ORDER");
                    Log.i("CLIENT_INSERT", msgs[1]);
                    Log.i("CLIENT_INSERT", msgs[2]);
                    Log.i("CLIENT_INSERT", msgs[3]);

                    String client = msgs[3];
                    String key = msgs[1];
                    String value = msgs[2];
                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(client));
                    socket.setSoTimeout(3000);
                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);
                    Message message = new Message("INSERT");
                    message.setKey(key);
                    message.setValue(value);

                    Log.i("Sending_Key_Insert",key +"  :  " + value);
                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();
                }
                else if(order.equals(QUERY)) {
                    String target = msgs[1];
                    String keyToFind = msgs[2];
                    String myPortId = msgs[3];

                    Message message = new Message("QUERY");
                    message.setAssociatedPort(myPortId);
                    message.setKeyToSearch(keyToFind);


                    if(queryGeneratedFrom != null) {
                        message.setQueryPort(queryGeneratedFrom);
                    }
                    else {
                        message.setQueryPort(myPortId);
                    }
                    Log.i("SEND_QUERY_MSG", msgs[1]);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(target));
                    socket.setSoTimeout(3000);
                    stream = socket.getOutputStream();


                    OutputStreamWriter out = new OutputStreamWriter(stream,
                            "UTF-8");
                    dos = new DataOutputStream(stream);

                    dos.writeUTF(message.getString());

                    stream.flush();
                    out.flush();

                }
                else if(order.equals("QUERY_ANSWER")) {
                    Message message = new Message("QUERY_ANSWER");

                    Log.i("SEND_QUERY_MSG_ANSWER", msgs[1]);

                    String target = msgs[1];
                    String keyToFind = msgs[2];
                    String value = msgs[4];

                    message.setKeyToSearch(keyToFind);
                    message.setQueryAnswer(value);

                    socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}),
                            Integer.parseInt(target));
                    socket.setSoTimeout(3000);
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



