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
package com.punyal.tentacle;

import static com.punyal.tentacle.constants.Defaults.*;
import com.punyal.tentacle.core.TentacleCLI;
import com.punyal.tentacle.core.Tentacle;
import com.punyal.tentacle.logger.TentacleLogger;
import com.punyal.tentacle.constants.Error;
import static com.punyal.tentacle.logger.TentacleLogger.GrainLevel.*;
import com.punyal.tentacle.utils.DateUtils;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.ParseException;

/**
 *
 * @author punyal
 */
public class Main {
    private static final TentacleLogger LOG = new TentacleLogger();
    private static Tentacle tentacle = null;
    
    public static void main(String[] args) {
        LOG.critical("Starting Tentacle...");
        TentacleCLI cli = new TentacleCLI();
        TentacleLogger.levelFilter = INF;
        
        try {
            CommandLine cmd = cli.getCLI(args);
            
            if (cmd.hasOption("help")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("Tentacle", cli.getOptions());
                System.exit(0);
            }
            
            if (cmd.hasOption("log")) {
                switch(cmd.getOptionValue("log").toLowerCase()) {
                    case "debug":
                        TentacleLogger.levelFilter = DEB;
                        break;
                    case "info":
                        TentacleLogger.levelFilter = INF;
                        break;
                    case "WAR":
                        TentacleLogger.levelFilter = WAR;
                        break;
                    case "ERROR":
                        TentacleLogger.levelFilter = ERR;
                        break;
                    case "CRITICAL":
                        TentacleLogger.levelFilter = CRI;
                        break;
                    default:
                        TentacleLogger.levelFilter = WAR;
                        break;    
                }
            }
        } catch (ParseException ex) {
            LOG.error("Parsing failed. Reason: "+ex.getMessage());
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("Tentacle", cli.getOptions());
            System.exit(1);
        }
        
        /* Initiate Console interface */
        boolean running = true;
        String input;
        List<String> commands;
        
        try {
            tentacle = new Tentacle();
        } catch (UnknownHostException ex) {
            LOG.critical("Medusa Host: "+ ex.getMessage());
            System.exit(-1);
        }
        
        /* Clear screen */
        final String ANSI_CLS = "\u001b[2J";
        final String ANSI_HOME = "\u001b[H";
        System.out.print(ANSI_CLS + ANSI_HOME);
        System.out.flush();
        
        printInfo();
            
        while (running) {
            /* Wait for new commmand */
            System.out.print(tentacle.getName()+"@"+tentacle.getMedusaHost()+":"+tentacle.getMedusaPort()+"{"+(tentacle.isAuthenticated()?"AUTH":"NON AUTH")+"}> $ ");
            input = System.console().readLine();
            
            commands = new ArrayList<>(Arrays.asList(input.split(" ")));
            switch (commands.get(0).toLowerCase()) {
                case "":
                        break;
                case "exit":
                    running = false;
                    break;
                case "authenticate":
                    int error = tentacle.authenticateCoAP();
                    if (error == Error.NO_ERROR.getCode())
                        System.out.print("You are now authenticated with Ticket ["+tentacle.getTicket()+"] till "+DateUtils.long2DateMillis(tentacle.getExpireTime())+"\n");
                    break;
                case "authorize":
                    System.out.print("Remote Address: ");
                    String remoteAddress = System.console().readLine();
                    System.out.print("Remote Ticket: ");
                    String remoteTicket = System.console().readLine();
                    System.out.println("Response: "+tentacle.checkAuthorization(remoteAddress, remoteTicket));
                    break;
                case "auto":
                    tentacle.automatic();
                    break;
                case "help":
                    printHelp();
                    break;
                case "info":
                    printInfo();
                    break;
                case "config":
                    
                    System.out.print("Medusa Host: ");
                    try {
                        tentacle.setMedusaHost(System.console().readLine());
                    } catch (UnknownHostException ex) {
                        LOG.critical("Medusa Host: "+ ex.getMessage());
                    }
                    System.out.print("Medusa Port: ");
                    try {
                        tentacle.setMedusaPort(Integer.parseInt(System.console().readLine()));
                    } catch (NumberFormatException ex) {
                        LOG.critical("Invalid port format, use default 5683");
                        tentacle.setMedusaPort(5683);
                    }
                    System.out.print("Secret key: ");
                    tentacle.setSecretKey(System.console().readLine());
                    System.out.print("User name: ");
                    tentacle.setName(System.console().readLine());
                    System.out.print("User password: ");
                    tentacle.setPassword(System.console().readLine());
                    break;
                default:
                    LOG.error("Unknown command ["+commands.get(0)+"]");
                    printHelp();
                    break;
            }
        }
        
    }
    
    private static void printHelp() {
        StringBuilder sb = new StringBuilder();
        sb.append("\nList of Commands\n-----------------\n");
        sb.append(padCommand("authenticate",    "Start authentication process"));
        sb.append(padCommand("authorize",       "Check authorization of other"));
        sb.append(padCommand("auto",            "Start auto-authentication process"));
        sb.append(padCommand("config",          "Configure tentacle and user params"));
        sb.append(padCommand("exit",            "Exit program"));
        sb.append(padCommand("info",            "Print Medusa info"));
        sb.append(padCommand("help",            "Show this info"));
        sb.append("\n");
        System.out.print(sb.toString());
    }
    
    private static String padCommand(String name, String definition) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("%1$-" + 26 + "s", name)).append(definition).append("\n");
        return sb.toString();
    }
    
    private static void printInfo() {
        StringBuilder sb = new StringBuilder();
        sb.append("Tentacle v").append(TENTACLE_VERSION).append(".").append(TENTACLE_SUBVERSION).append(" [CommandLine demo]").append("\n");
        sb.append("Bugs? contact me: <pablo.punal@ltu.se>\n\n");
        sb.append(tentacle.toString());
        sb.append("\n");
        System.out.print(sb.toString());
    }
}
