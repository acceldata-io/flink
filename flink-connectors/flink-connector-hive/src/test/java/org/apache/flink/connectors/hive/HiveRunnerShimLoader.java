/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.connectors.hive;

import org.apache.flink.table.catalog.hive.client.HiveShimLoader;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** Loader to load proper HiveRunnerShim. */
public class HiveRunnerShimLoader {

    private static final Map<String, HiveRunnerShim> hiveRunnerShims = new ConcurrentHashMap<>();

    private HiveRunnerShimLoader() {}

    public static HiveRunnerShim load() {
        String hiveVersion = HiveShimLoader.getHiveVersion();
        return hiveRunnerShims.computeIfAbsent(
                hiveVersion,
                v -> {
                    switch (v) {
                        case HiveShimLoader.HIVE_VERSION_V2_3_0:
                        case HiveShimLoader.HIVE_VERSION_V2_3_1:
                        case HiveShimLoader.HIVE_VERSION_V2_3_2:
                        case HiveShimLoader.HIVE_VERSION_V2_3_3:
                        case HiveShimLoader.HIVE_VERSION_V2_3_4:
                        case HiveShimLoader.HIVE_VERSION_V2_3_5:
                        case HiveShimLoader.HIVE_VERSION_V2_3_6:
                        case HiveShimLoader.HIVE_VERSION_V2_3_7:
                        case HiveShimLoader.HIVE_VERSION_V2_3_8:
                        case HiveShimLoader.HIVE_VERSION_V2_3_9:
                        case HiveShimLoader.HIVE_VERSION_V3_1_0:
                        case HiveShimLoader.HIVE_VERSION_V3_1_1:
                        case HiveShimLoader.HIVE_VERSION_V3_1_2:
                        case HiveShimLoader.HIVE_VERSION_V3_1_3:
                        case HiveShimLoader.HIVE_VERSION_V4_0_0:
                            return new HiveRunnerShimV4();
                        default:
                            throw new RuntimeException("Unsupported Hive version " + v);
                    }
                });
    }
}
