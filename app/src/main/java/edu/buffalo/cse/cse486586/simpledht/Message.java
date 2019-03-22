package edu.buffalo.cse.cse486586.simpledht;

public class Message {

    private String messageType = null;
    private String client =null;

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    String key = null, value= null;
    public String getConnectedClients() {
        return connectedClients;
    }

    public void setConnectedClients(String[] connectedClients) {
        StringBuilder sb = new StringBuilder();
        for(int i=0;i<connectedClients.length;i++){
            String client = connectedClients[i];
            sb.append(client);
            if(i!=connectedClients.length-1){
                sb.append(",");
            }
        }
//        for(String client : connectedClients) {
//            sb.append(client);
//            sb.append(",");
//        }
        this.connectedClients = sb.toString();
    }

    String connectedClients=null;

    public String getClient() {
        return client;
    }

    public void setClient(String client) {
        this.client = client;
    }


    public String getMessageType() {
        return messageType;
    }

    public void setMessageType(String messageType) {
        this.messageType = messageType;
    }


    public Message(String type){
        messageType = type;
    }

    public String getString() {
        StringBuilder sb = new StringBuilder();
        if(this.messageType != null) {
            sb.append("messageType:" + this.messageType);
            //sb.append(this.messageType);
            sb.append(";");
        }
        if(this.client != null) {
            sb.append("client:" + this.client);
            sb.append(";");
        }
        if(this.connectedClients != null) {
            sb.append("connectedClinets:" + this.connectedClients);
        }
        if(this.key != null) {
            sb.append("key:" + this.key);
            sb.append(";");
        }
        if(this.value != null) {
            sb.append("value:" + this.value);
            sb.append(";");
        }
        return sb.toString();
    }
}
