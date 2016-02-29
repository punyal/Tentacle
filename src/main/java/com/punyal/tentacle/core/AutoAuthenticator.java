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

import com.punyal.tentacle.logger.TentacleLogger;
import com.punyal.tentacle.constants.Error;
import com.punyal.tentacle.utils.DateUtils;

/**
 *
 * @author Pablo Puñal Pereira <pablo.punal@ltu.se>
 */
public class AutoAuthenticator implements Runnable {
    private static final TentacleLogger LOG = new TentacleLogger();
    private final Tentacle tentacle;
    
    private long timeout;
    
    public AutoAuthenticator(Tentacle tentacle) {
        this.tentacle = tentacle;
        timeout = 0;
    }
    
    @Override
    public void run() {
        while(true) {
            try {
                
                if (tentacle.authenticateCoAP() == Error.NO_ERROR.getCode())
                    LOG.info("You are now authenticated with Ticket ["+tentacle.getTicket()+"] till "+DateUtils.long2DateMillis(tentacle.getExpireTime())+"\n");
                timeout = tentacle.getExpireTime() - System.currentTimeMillis();
                if (timeout < 1000) timeout = 1000;
                Thread.sleep(timeout);
            } catch (InterruptedException ex) {
                LOG.critical("AutoAuthenticate: "+ex.getMessage());
            }
        }
    }
    
}
