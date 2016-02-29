/*
 * The MIT License
 *
 * Copyright 2016 Pablo Puñal Pereira <pablo.punal@ltu.se>.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package com.punyal.tentacle.core;

import static com.punyal.tentacle.constants.Defaults.*;
import com.punyal.tentacle.constants.Error;
import com.punyal.tentacle.constants.Warning;
import static com.punyal.tentacle.constants.JsonKeys.*;
import com.punyal.tentacle.logger.TentacleLogger;
import com.punyal.tentacle.utils.DataUtils;
import com.punyal.tentacle.utils.DateUtils;
import com.punyal.tentacle.utils.JsonUtils;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import org.json.simple.JSONObject;

/**
 *
 * @author Pablo Puñal Pereira <pablo.punal@ltu.se>
 */
public class Tentacle {
    private static final TentacleLogger LOG = new TentacleLogger();
    private String name;
    private String password;
    private InetAddress medusaHost;
    private int medusaPort;
    private String secretKey;
    private String authenticator;
    private int timeout;
    private long expireTime;
    private String ticket;
    
    private final AutoAuthenticator auto;
    // CoAP protocol
    private CoapClient coapClient;
    private CoapResponse coapResponse;
    
    public Tentacle() throws UnknownHostException { // Load defaults
        Logger.getGlobal().setLevel(Level.OFF);
        Logger.getLogger("org.eclipse.californium.core.network.config.NetworkConfig").setLevel(Level.OFF);
        Logger.getLogger("org.eclipse.californium.core.network.CoapEndpoint").setLevel(Level.OFF);
        Logger.getLogger("org.eclipse.californium.core.network.EndpointManager").setLevel(Level.OFF);
        
        name = DEFAULT_NAME;
        password = DEFAULT_PASSWORD;
        medusaHost = InetAddress.getByName(DEFAULT_MEDUSA_HOST);
        medusaPort = DEFAULT_MEDUSA_PORT;
        secretKey = DEFAULT_SECRET_KEY;
        authenticator = "";
        timeout = 0;
        expireTime = 0;
        ticket = "";
        auto = new AutoAuthenticator(this);
    }
    
    
    public void setName(String name) {
        this.name = name;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }
    
    public void setMedusaHost(String medusaHost) throws UnknownHostException {
        this.medusaHost = InetAddress.getByName(medusaHost);
    }
    
    public void setMedusaPort(int medusaPort) {
        this.medusaPort = medusaPort;
    } 
    
    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }
    
    public String getName() {
        return name;
    }
    
    public String getMedusaHost() {
        return medusaHost.getHostName();
    }
    
    public int getMedusaPort() {
        return medusaPort;
    }
    
    public String getTicket() {
        return ticket;
    }
    
    public long getExpireTime() {
        return expireTime;
    }
    
    public boolean isAuthenticated() {
        return (expireTime > System.currentTimeMillis()) && !ticket.isEmpty();
    }
    
    public void automatic() {
        auto.run();
    }
    
    public int authenticateCoAP() {
        LOG.info("Authenticating using CoAP");
        int error = getAuthenticator();
        
        if (error != Error.NO_ERROR.getCode()) {
            LOG.critical("Error with Challenge-Response step");
            return error;
        }
        error = requestTicket();
        
        return error;
    }
    
    private int getAuthenticator() {
        LOG.debug("get new Authenticator");
        
        String uri = (medusaHost instanceof Inet6Address)?
                "coap://["+medusaHost.getHostAddress()+"]:"+medusaPort+"/"+DEFAULT_AUTHENTICATION_RESOURCE:
                "coap://"+medusaHost.getHostAddress()+":"+medusaPort+"/"+DEFAULT_AUTHENTICATION_RESOURCE;
        
        coapClient = new CoapClient(uri);
        LOG.debug("CoAPClient URI: "+coapClient.getURI());
        coapResponse = coapClient.get();
        
        // Check if response is null
        if (coapResponse == null) {
            LOG.critical(Error.SERVER_NOT_RESPONDING.toString());
            return Error.SERVER_NOT_RESPONDING.getCode();
        }
        
        // Check if response is JSON
        if (coapResponse.getOptions().getContentFormat() != APPLICATION_JSON) {
            LOG.critical(Error.RESPONSE_NO_JSON_FORMAT.toString());
            return Error.RESPONSE_NO_JSON_FORMAT.getCode();
        }
        
        LOG.debug(coapResponse.getResponseText());
        
        // Check parsing
        JSONObject jsonResponse = JsonUtils.parseString(coapResponse.getResponseText());
        LOG.debug(jsonResponse.toJSONString());
        if (jsonResponse == null) {
            LOG.critical(Error.RESPONSE_NO_JSON_PARSEABLE.toString());
            return Error.RESPONSE_NO_JSON_PARSEABLE.getCode();
        }
        
        // Check version
        String version = (jsonResponse.get(JSON_KEY_VERSION) != null)?jsonResponse.get(JSON_KEY_VERSION).toString():"";
        if (!version.equals(SUPORTS_MEDUSA_VERSION)) {
            LOG.warning(Warning.NO_SAME_VERSION.toString());
        }
        
        // Check timeout and Authenticator
        authenticator = (jsonResponse.get(JSON_KEY_AUTHENTICATOR) != null)?jsonResponse.get(JSON_KEY_AUTHENTICATOR).toString():"";
        if (authenticator.equals("")) {
            LOG.critical(Error.NO_AUTHENTICATOR.toString());
            return Error.NO_AUTHENTICATOR.getCode();
        }
        timeout = (jsonResponse.get(JSON_KEY_TIMEOUT) != null)?Integer.parseInt(jsonResponse.get(JSON_KEY_TIMEOUT).toString()):0;
        if (timeout == 0) {
            LOG.critical(Error.NO_TIMEOUT.toString());
            return Error.NO_TIMEOUT.getCode();
        }
        
        LOG.debug("Got valid Authenticator ["+authenticator+"] till "+DateUtils.long2DateMillis(System.currentTimeMillis()+timeout));
        
        return Error.NO_ERROR.getCode();
    }
    
    private int requestTicket() {
        JSONObject jsonRequest = new JSONObject();
        jsonRequest.put(JSON_KEY_NAME, name);
        jsonRequest.put(JSON_KEY_PASSWORD, encrypt());
        LOG.debug("Encrypted Password ["+encrypt()+"]");
        
        String uri = (medusaHost instanceof Inet6Address)?
                "coap://["+medusaHost.getHostAddress()+"]:"+medusaPort+"/"+DEFAULT_AUTHENTICATION_RESOURCE:
                "coap://"+medusaHost.getHostAddress()+":"+medusaPort+"/"+DEFAULT_AUTHENTICATION_RESOURCE;
        
        coapClient = new CoapClient(uri);
        LOG.debug(coapClient.getURI());
        
        coapResponse = coapClient.post(jsonRequest.toJSONString(), APPLICATION_JSON);
        
        // Check if response is null
        if (coapResponse == null) {
            LOG.critical(Error.SERVER_NOT_RESPONDING.toString());
            return Error.SERVER_NOT_RESPONDING.getCode();
        }
        
        LOG.debug(coapResponse.getResponseText());
        
        // Check if response is JSON
        if (coapResponse.getOptions().getContentFormat() != APPLICATION_JSON) {
            LOG.critical(Error.RESPONSE_NO_JSON_FORMAT.toString());
            return Error.RESPONSE_NO_JSON_FORMAT.getCode();
        }
        
        LOG.debug(coapResponse.getResponseText());
        
        // Check parsing
        JSONObject jsonResponse = JsonUtils.parseString(coapResponse.getResponseText());
        LOG.debug(jsonResponse.toJSONString());
        if (jsonResponse == null) {
            LOG.critical(Error.RESPONSE_NO_JSON_PARSEABLE.toString());
            return Error.RESPONSE_NO_JSON_PARSEABLE.getCode();
        }
        
        // Check server errors
        String serverError = (jsonResponse.get(JSON_KEY_ERROR) != null)?jsonResponse.get(JSON_KEY_ERROR).toString():"";
        if (!serverError.equals("")) {
            LOG.error("Remote Error "+serverError);
            return Error.SERVER_ERROR.getCode();
        }
        
        // Check expireTime and ticket
        ticket = (jsonResponse.get(JSON_KEY_TICKET) != null)?jsonResponse.get(JSON_KEY_TICKET).toString():"";
        if (ticket.equals("")) {
            LOG.critical(Error.NO_TICKET.toString());
            return Error.NO_TICKET.getCode();
        }
        expireTime = (jsonResponse.get(JSON_KEY_EXPIRE_TIME) != null)?Long.parseLong(jsonResponse.get(JSON_KEY_EXPIRE_TIME).toString()):0;
        if (expireTime == 0) {
            LOG.critical(Error.NO_EXPIRE_TIME.toString());
            return Error.NO_EXPIRE_TIME.getCode();
        }
                
        return Error.NO_ERROR.getCode();
    }
    
    private String encrypt() {
        try {
            LOG.debug("encrypt secretKey["+secretKey+"] authenticator["+authenticator+"] password["+password+"]");
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] b_secretKey = DataUtils.string2byteArray(secretKey);
            byte[] b_authenticator = DataUtils.hexString2byteArray(authenticator);
            byte[] b_password = DataUtils.string2byteArray(password);
            
            if (b_authenticator.length != 16) {
                LOG.critical("Authenticator with wrong length!");
                return null;
            }
            
            int len = 0, tot_len = 0;
            
            // Check final length to prevent errors;
            if (b_password.length%16!=0) tot_len = 16;
            tot_len += ((int)b_password.length/16)*16;
            
            // Create crypted array
            byte[] crypted = new byte[tot_len];
            byte[] b_tmp = new byte[b_secretKey.length+b_authenticator.length];
            byte[] c_tmp = new byte[16];
            
            System.arraycopy(b_secretKey, 0, b_tmp, 0, b_secretKey.length);
            System.arraycopy(b_authenticator, 0, b_tmp, b_secretKey.length, b_authenticator.length);
            b_tmp = md.digest(DataUtils.string2byteArray(DataUtils.byteArray2hexString(b_tmp)));
            
            while (len < tot_len) {
                if((b_password.length - len) < 16) {
                    System.arraycopy(b_password, len, c_tmp, 0, b_password.length-len);
                    for (int i=b_password.length-len; i<16; i++)
                        c_tmp[i] = 0;
                } else System.arraycopy(b_password, len, c_tmp, 0, 16);
                for (int i=0; i<16; i++)
                    c_tmp[i] = (byte)(0xFF & ((int)c_tmp[i])^((int)b_tmp[i]));
                System.arraycopy(c_tmp, 0, crypted, len, 16);
                len += 16;
            }
            LOG.debug("Encrypted: "+DataUtils.byteArray2hexString(crypted));
            return DataUtils.byteArray2hexString(crypted);
            
        } catch (NoSuchAlgorithmException ex) {
            LOG.critical("Encrypt: "+ex.getMessage());
            return null;
        }
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[Medusa Server info]\n");
        sb.append(" Host: ").append(medusaHost.getHostName()).append("\n");
        sb.append(" Port: ").append(medusaPort).append("\n");
        sb.append(" Secret key: ").append(secretKey.replaceAll("(?s).", "*")).append("\n");
        sb.append("[Account info]\n");
        sb.append(" Name: ").append(name).append("\n");
        sb.append(" Password: ").append(password.replaceAll("(?s).", "*")).append("\n");
        sb.append("[Ticket info]\n");
        sb.append(" Value: ").append(ticket).append("\n");
        sb.append(" Expire: ").append((expireTime > System.currentTimeMillis()?DateUtils.long2DateMillis(expireTime):"expired")).append("\n");
        return sb.toString();
    }
    
}
