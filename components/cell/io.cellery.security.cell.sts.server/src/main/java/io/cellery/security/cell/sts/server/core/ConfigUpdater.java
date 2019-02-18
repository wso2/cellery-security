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

import io.cellery.security.cell.sts.server.core.service.CelleryCellSTSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.List;

/**
 * Updates configuration by watching config file changes in the file system.
 */
public class ConfigUpdater implements Runnable {

    private static final Logger log = LoggerFactory.getLogger(ConfigUpdater.class);

    public void run() {

        log.info("Running configuration updater..");
        String configFilePath = CellStsUtils.getConfigFilePath();
        Path myDir = Paths.get(configFilePath.substring(0, configFilePath.lastIndexOf("/")));
        try {
            while (true) {
                WatchService watcher = myDir.getFileSystem().newWatchService();
                myDir.register(watcher, StandardWatchEventKinds.ENTRY_CREATE,
                        StandardWatchEventKinds.ENTRY_DELETE, StandardWatchEventKinds.ENTRY_MODIFY);

                log.debug("Waiting for config file change");
                WatchKey watckKey = watcher.take();

                List<WatchEvent<?>> events = watckKey.pollEvents();
                log.debug("Received events: ....");
                for (WatchEvent event : events) {
                    if (event.kind() == StandardWatchEventKinds.ENTRY_CREATE) {
                        log.info("Updating file on {} event", StandardWatchEventKinds.ENTRY_CREATE);
                        CellStsUtils.buildCellStsConfiguration();
                    }
                    if (event.kind() == StandardWatchEventKinds.ENTRY_MODIFY) {
                        log.info("Updating file on {} event", StandardWatchEventKinds.ENTRY_MODIFY);
                        CellStsUtils.buildCellStsConfiguration();
                    }
                }

            }
        } catch (IOException | InterruptedException | CelleryCellSTSException e) {
            log.error("Error while updating configurations on file change ", e);
        }
    }
}
