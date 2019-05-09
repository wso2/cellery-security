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

package io.cellery.security.cell.sts.server.core.context.store;

import org.testng.Assert;
import org.testng.annotations.AfterTest;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

/**
 * Test class for Context Store.
 */

public class UserContextStoreImplTest {

    UserContextStore userContextStore;
    private static final String CACHE_KEY = "randomCacheKey";
    private static final String CACHE_VALUE = "randomCacheValue";
    private static final String USER_CONTEXT_EXPIRY_IN_SECONDS = "USER_CONTEXT_EXPIRY_SECONDS";

    @BeforeTest
    public void setUp() throws Exception {

        System.setProperty(USER_CONTEXT_EXPIRY_IN_SECONDS, "2");
        userContextStore = new UserContextStoreImpl();
    }

    @Test
    public void testGet() throws Exception {

        userContextStore.put(CACHE_KEY, CACHE_VALUE);
        Assert.assertEquals(CACHE_VALUE, userContextStore.get(CACHE_KEY));
        // Wait until cache expires.
        Thread.sleep(2500);
        Assert.assertNull(userContextStore.get(CACHE_KEY));
    }

    @Test
    public void testContainsKey() throws Exception {

        userContextStore.put(CACHE_KEY, CACHE_VALUE);
        Assert.assertTrue(userContextStore.containsKey(CACHE_KEY));
        // Wait until cache expires.
        Thread.sleep(2500);
        Assert.assertFalse(userContextStore.containsKey(CACHE_KEY));
    }

    @Test
    public void testRemove() throws Exception {

        userContextStore.put(CACHE_KEY, CACHE_VALUE);
        Assert.assertTrue(userContextStore.containsKey(CACHE_KEY));
        userContextStore.remove(CACHE_KEY);
        Assert.assertFalse(userContextStore.containsKey(CACHE_KEY));
    }

    @AfterTest
    public void tearDown() throws Exception {

        System.getProperties().remove(USER_CONTEXT_EXPIRY_IN_SECONDS);
        userContextStore = null;
    }

}
