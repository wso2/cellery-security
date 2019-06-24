/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package io.cellery.security.cell.sts.server.core;

import io.cellery.security.cell.sts.server.core.context.store.UserContextStore;
import io.cellery.security.cell.sts.server.core.context.store.UserContextStoreImpl;
import io.cellery.security.cell.sts.server.core.service.CelleryCellInboundInterceptorService;
import io.cellery.security.cell.sts.server.core.service.CelleryCellOutboundInterceptorService;
import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import io.cellery.security.cell.sts.server.core.service.CelleryCellStsService;
import io.cellery.security.cell.sts.server.core.service.CelleryGWInboundInterceptorService;
import io.cellery.security.cell.sts.server.core.service.CelleryGWSTSService;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

/**
 * Intercepts outbound calls from micro service proxy.
 */
public class CelleryCellSTSServer {

    private static final String CELL_NAME_ENV_VARIABLE = "CELL_NAME";
    private static final Logger log = LoggerFactory.getLogger(CelleryCellSTSServer.class);

    private final int inboundListeningPort;
    private final Server inboundListener;

    private final int outboundListeningPort;
    private final Server outboundListener;

    private final Server gatewayListner;
    private final int gatewayListeningPort;

    private CelleryCellSTSServer(int inboundListeningPort, int outboundListeningPort, int gatewayListeningPort) throws
            CelleryCellSTSException {

        CellStsUtils.buildCellStsConfiguration();
        CellStsUtils.readUnsecuredContexts();
        UserContextStore contextStore = new UserContextStoreImpl();
        UserContextStore localContextStore = new UserContextStoreImpl();

        CelleryCellStsService cellStsService = new CelleryCellStsService(contextStore, localContextStore);
        CelleryGWSTSService celleryGWSTSService = new CelleryGWSTSService(contextStore, localContextStore);

        this.inboundListeningPort = inboundListeningPort;
        inboundListener = ServerBuilder.forPort(inboundListeningPort)
                .addService(new CelleryCellInboundInterceptorService(cellStsService))
                .build();

        this.outboundListeningPort = outboundListeningPort;
        outboundListener = ServerBuilder.forPort(outboundListeningPort)
                .addService(new CelleryCellOutboundInterceptorService(cellStsService))
                .build();

        this.gatewayListeningPort = gatewayListeningPort;
        gatewayListner = ServerBuilder.forPort(gatewayListeningPort)
                .addService(new CelleryGWInboundInterceptorService(celleryGWSTSService))
                .build();
    }

    /**
     * Start serving requests.
     */
    private void start() throws IOException {

        inboundListener.start();
        outboundListener.start();
        gatewayListner.start();
        log.info("Cellery STS gRPC Server started, listening for inbound traffic on " + inboundListeningPort);
        log.info("Cellery STS gRPC Server started, listening for outbound traffic on " + outboundListeningPort);
        log.info("Cellery STS gRPC Server started, listening for gateway inbound traffic on " + gatewayListeningPort);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            // Use stderr here since the logger may has been reset by its JVM shutdown hook.
            log.error("Shutting down Cellery Cell STS since JVM is shutting down.");
            CelleryCellSTSServer.this.stop();
            log.error("Cellery Cell STS shut down.");
        }));
    }

    /**
     * Stop serving requests and shutdown resources.
     */
    private void stop() {

        if (inboundListener != null) {
            inboundListener.shutdown();
        }

        if (outboundListener != null) {
            outboundListener.shutdown();
        }

        if (gatewayListner != null) {
            gatewayListner.shutdown();
        }
    }

    /**
     * Await termination on the main thread since the grpc library uses daemon threads.
     */
    private void blockUntilShutdown() throws InterruptedException {

        if (inboundListener != null) {
            inboundListener.awaitTermination();
        }

        if (outboundListener != null) {
            outboundListener.awaitTermination();
        }

        if (gatewayListner != null) {
            gatewayListner.awaitTermination();
        }
    }

    public static void main(String[] args) {

        CelleryCellSTSServer server;
        int inboundListeningPort = getPortFromEnvVariable("inboundPort", 8080);
        int outboundListeningPort = getPortFromEnvVariable("outboundPort", 8081);
        int gatewayInboundPort = getPortFromEnvVariable("gatewayInboundPort", 8082);

        try {
            server = new CelleryCellSTSServer(inboundListeningPort, outboundListeningPort, gatewayInboundPort);
            server.start();
            watchConfigChanges();
            server.blockUntilShutdown();
        } catch (CelleryCellSTSException | IOException | InterruptedException e) {
            log.error("Error while starting up the Cell STS.", e);
            // To make the pod go to CrashLoopBackOff state if we encounter any error while starting up
            System.exit(1);
        }

    }

    private static int getPortFromEnvVariable(String name, int defaultPort) {

        if (StringUtils.isNotEmpty(System.getenv(name))) {
            defaultPort = Integer.parseInt(System.getenv(name));
        }
        log.info("Port for {} : {}", name, defaultPort);
        return defaultPort;
    }

    private static void watchConfigChanges() {

        Thread fileWatcher = new Thread(new ConfigUpdater());
        fileWatcher.start();
    }

}
