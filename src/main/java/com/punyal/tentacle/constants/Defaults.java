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
package com.punyal.tentacle.constants;

/**
 *
 * @author Pablo Puñal Pereira <pablo.punal@ltu.se>
 */
public class Defaults {
    public static final int TENTACLE_VERSION = 0;
    public static final int TENTACLE_SUBVERSION = 1;
    
    public static final String SUPORTS_MEDUSA_VERSION = "2.1";
        
    public static final String DEFAULT_CHARSET = "UTF-8";
    
    public static final String DEFAULT_AUTHENTICATION_RESOURCE = "Authentication";
    public static final String DEFAULT_AUTHORIZATION_RESOURCE = "Authorization";
    
    /* CoAP */
    public static final int DEFAULT_COAP_TICKET_OPTION = 100;
    
    /* Auth params */
    public static final String DEFAULT_NAME = "default";
    public static final String DEFAULT_PASSWORD = "default";
    public static final String DEFAULT_MEDUSA_HOST = "localhost";
    public static final int    DEFAULT_MEDUSA_PORT = 5683;
    public static final String DEFAULT_SECRET_KEY = "default";
}
