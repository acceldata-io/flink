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

package org.apache.flink.table.catalog.hive;

import org.apache.flink.configuration.BatchExecutionOptions;
import org.apache.flink.configuration.CoreOptions;
import org.apache.flink.configuration.JobManagerOptions;
import org.apache.flink.configuration.MemorySize;
import org.apache.flink.streaming.api.environment.StreamExecutionEnvironment;
import org.apache.flink.table.api.EnvironmentSettings;
import org.apache.flink.table.api.Schema;
import org.apache.flink.table.api.SqlDialect;
import org.apache.flink.table.api.TableEnvironment;
import org.apache.flink.table.api.bridge.java.StreamTableEnvironment;
import org.apache.flink.table.api.internal.TableEnvironmentInternal;
import org.apache.flink.table.catalog.CatalogTest;
import org.apache.flink.table.catalog.ObjectPath;
import org.apache.flink.table.catalog.exceptions.CatalogException;
import org.apache.flink.table.catalog.hive.client.HiveShimLoader;
import org.apache.flink.table.delegation.Parser;
import org.apache.flink.table.operations.ddl.AddPartitionsOperation;
import org.apache.flink.table.types.DataType;
import org.apache.flink.table.utils.PartitionPathUtils;
import org.apache.flink.util.Preconditions;
import org.apache.flink.util.StringUtils;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hive.conf.HiveConf;
import org.apache.hadoop.hive.metastore.api.Table;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

import static org.apache.flink.table.api.config.ExecutionConfigOptions.TABLE_EXEC_RESOURCE_DEFAULT_PARALLELISM;

/** Test utils for Hive connector. */
public class HiveTestUtils {
    private static final String HIVE_WAREHOUSE_URI_FORMAT =
            "jdbc:derby:;databaseName=%s;create=true";
    private static final TemporaryFolder TEMPORARY_FOLDER = new TemporaryFolder();

    // range of ephemeral ports
    private static final int MIN_EPH_PORT = 49152;
    private static final int MAX_EPH_PORT = 61000;

    private static final byte[] SEPARATORS =
            new byte[] {
                (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6, (byte) 7, (byte) 8
            };

    /** Create a HiveCatalog with an embedded Hive Metastore. */
    public static HiveCatalog createHiveCatalog() {
        return createHiveCatalog(CatalogTest.TEST_CATALOG_NAME, null);
    }

    public static HiveCatalog createHiveCatalog(String name, String hiveVersion) {
        return new HiveCatalog(
                name,
                null,
                createHiveConf(),
                StringUtils.isNullOrWhitespaceOnly(hiveVersion)
                        ? HiveShimLoader.getHiveVersion()
                        : hiveVersion,
                true);
    }

    public static HiveCatalog createHiveCatalog(
            String name, String hiveConfDir, String hadoopConfDir, String hiveVersion) {
        return new HiveCatalog(
                name,
                null,
                hiveConfDir,
                hadoopConfDir,
                StringUtils.isNullOrWhitespaceOnly(hiveVersion)
                        ? HiveShimLoader.getHiveVersion()
                        : hiveVersion);
    }

    public static HiveCatalog createHiveCatalog(HiveConf hiveConf) {
        return new HiveCatalog(
                CatalogTest.TEST_CATALOG_NAME,
                null,
                hiveConf,
                HiveShimLoader.getHiveVersion(),
                true);
    }

    public static HiveConf createHiveConf() {
        ClassLoader classLoader = HiveTestUtils.class.getClassLoader();

        try {
            TEMPORARY_FOLDER.create();
            String warehouseDir = TEMPORARY_FOLDER.newFolder().getAbsolutePath() + "/metastore_db";
            String warehouseUri = String.format(HIVE_WAREHOUSE_URI_FORMAT, warehouseDir);

            HiveConf.setHiveSiteLocation(classLoader.getResource(HiveCatalog.HIVE_SITE_FILE));
            HiveConf hiveConf = new HiveConf();
            hiveConf.setVar(
                    HiveConf.ConfVars.METASTORE_WAREHOUSE,
                    TEMPORARY_FOLDER.newFolder("hive_warehouse").getAbsolutePath());
            hiveConf.setVar(HiveConf.ConfVars.METASTORE_CONNECT_URL_KEY, warehouseUri);
            return hiveConf;
        } catch (IOException e) {
            throw new CatalogException("Failed to create test HiveConf to HiveCatalog.", e);
        }
    }

    // Gets a free port of localhost. Note that this method suffers the "time of check to time of
    // use" race condition.
    // Use it as best efforts to avoid port conflicts.
    public static int getFreePort() throws IOException {
        final int numPorts = MAX_EPH_PORT - MIN_EPH_PORT + 1;
        int numAttempt = 0;
        while (numAttempt++ < numPorts) {
            int p = ThreadLocalRandom.current().nextInt(numPorts) + MIN_EPH_PORT;
            try (ServerSocket socket = new ServerSocket()) {
                socket.bind(new InetSocketAddress("localhost", p));
                return socket.getLocalPort();
            } catch (BindException e) {
                // this port is in use, try another one
            }
        }
        throw new RuntimeException("Exhausted all ephemeral ports and didn't find a free one");
    }

    public static TableEnvironment createTableEnvInBatchMode() {
        return createTableEnvInBatchMode(SqlDialect.DEFAULT);
    }

    public static TableEnvironment createTableEnvInBatchMode(SqlDialect dialect) {
        TableEnvironment tableEnv = TableEnvironment.create(EnvironmentSettings.inBatchMode());
        tableEnv.getConfig().set(TABLE_EXEC_RESOURCE_DEFAULT_PARALLELISM, 1);
        tableEnv.getConfig().setSqlDialect(dialect);
        return tableEnv;
    }

    public static TableEnvironment createTableEnvInBatchModeWithAdaptiveScheduler() {
        EnvironmentSettings settings = EnvironmentSettings.inBatchMode();
        settings.getConfiguration()
                .set(JobManagerOptions.SCHEDULER, JobManagerOptions.SchedulerType.AdaptiveBatch);
        settings.getConfiguration()
                .set(BatchExecutionOptions.ADAPTIVE_AUTO_PARALLELISM_MAX_PARALLELISM, 4);
        settings.getConfiguration()
                .set(
                        BatchExecutionOptions.ADAPTIVE_AUTO_PARALLELISM_AVG_DATA_VOLUME_PER_TASK,
                        MemorySize.parse("150kb"));
        settings.getConfiguration().set(CoreOptions.DEFAULT_PARALLELISM, -1);
        TableEnvironment tableEnv = TableEnvironment.create(settings);
        tableEnv.getConfig().setSqlDialect(SqlDialect.DEFAULT);
        return tableEnv;
    }

    public static StreamTableEnvironment createTableEnvInStreamingMode(
            StreamExecutionEnvironment env) {
        return createTableEnvInStreamingMode(env, SqlDialect.DEFAULT);
    }

    public static StreamTableEnvironment createTableEnvInStreamingMode(
            StreamExecutionEnvironment env, SqlDialect dialect) {
        StreamTableEnvironment tableEnv = StreamTableEnvironment.create(env);
        tableEnv.getConfig().set(TABLE_EXEC_RESOURCE_DEFAULT_PARALLELISM, 1);
        tableEnv.getConfig().setSqlDialect(dialect);
        return tableEnv;
    }

    public static TableEnvironment createTableEnvWithHiveCatalog(HiveCatalog catalog) {
        TableEnvironment tableEnv = HiveTestUtils.createTableEnvInBatchMode();
        tableEnv.registerCatalog(catalog.getName(), catalog);
        tableEnv.useCatalog(catalog.getName());
        return tableEnv;
    }

    // Insert into a single partition of a text table.
    public static TextTableInserter createTextTableInserter(
            HiveCatalog hiveCatalog, String dbName, String tableName) {
        return new TextTableInserter(hiveCatalog, dbName, tableName);
    }

    /** insert table operation. */
    public static class TextTableInserter {

        private final HiveCatalog hiveCatalog;
        private final TableEnvironment tableEnv;
        private final String dbName;
        private final String tableName;
        private final List<Object[]> rows;

        public TextTableInserter(HiveCatalog hiveCatalog, String dbName, String tableName) {
            this.hiveCatalog = hiveCatalog;
            tableEnv = createTableEnvWithHiveCatalog(hiveCatalog);
            tableEnv.getConfig().setSqlDialect(SqlDialect.HIVE);
            this.dbName = dbName;
            this.tableName = tableName;
            rows = new ArrayList<>();
        }

        public TextTableInserter addRow(Object[] row) {
            rows.add(row);
            return this;
        }

        public void commit() throws Exception {
            commit(null);
        }

        public void commit(String partitionSpec) throws Exception {
            File file = File.createTempFile("table_data_", null);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                for (int i = 0; i < rows.size(); i++) {
                    if (i > 0) {
                        writer.newLine();
                    }
                    writer.write(toText(rows.get(i)));
                }
                // new line at the end of file
                writer.newLine();
            }
            Path src = new Path(file.toURI());
            Path dest;
            ObjectPath tablePath = new ObjectPath(dbName, tableName);
            Table hiveTable = hiveCatalog.getHiveTable(tablePath);
            String addPartDDL = null;
            if (partitionSpec != null) {
                addPartDDL =
                        String.format(
                                "alter table `%s`.`%s` add if not exists partition (%s)",
                                dbName, tableName, partitionSpec);
                Parser parser = ((TableEnvironmentInternal) tableEnv).getParser();
                AddPartitionsOperation addPartitionsOperation =
                        (AddPartitionsOperation) parser.parse(addPartDDL).get(0);
                LinkedHashMap<String, String> spec =
                        new LinkedHashMap<>(
                                addPartitionsOperation
                                        .getPartitionSpecs()
                                        .get(0)
                                        .getPartitionSpec());
                Path partLocation =
                        new Path(
                                hiveTable.getSd().getLocation(),
                                PartitionPathUtils.generatePartitionPath(spec));
                dest = new Path(partLocation, src.getName());
            } else {
                dest = new Path(hiveTable.getSd().getLocation(), src.getName());
            }
            FileSystem fs = dest.getFileSystem(hiveCatalog.getHiveConf());
            Preconditions.checkState(fs.rename(src, dest));
            if (addPartDDL != null) {
                tableEnv.executeSql(
                        addPartDDL + String.format(" location '%s'", dest.getParent().toString()));
            }
        }

        private String toText(Object[] row) {
            StringBuilder builder = new StringBuilder();
            for (Object col : row) {
                if (builder.length() > 0) {
                    builder.appendCodePoint(SEPARATORS[0]);
                }
                String colStr = toText(col, 1);
                if (colStr != null) {
                    builder.append(colStr);
                }
            }
            return builder.toString();
        }

        private String toText(Object obj, final int level) {
            if (obj == null) {
                return null;
            }
            StringBuilder builder = new StringBuilder();
            if (obj instanceof Map) {
                for (Object key : ((Map) obj).keySet()) {
                    if (builder.length() > 0) {
                        builder.appendCodePoint(SEPARATORS[level]);
                    }
                    builder.append(toText(key, level + 2));
                    builder.appendCodePoint(SEPARATORS[level + 1]);
                    builder.append(toText(((Map) obj).get(key), level + 2));
                }
            } else if (obj instanceof Object[]) {
                Object[] array = (Object[]) obj;
                for (Object element : array) {
                    if (builder.length() > 0) {
                        builder.appendCodePoint(SEPARATORS[level]);
                    }
                    builder.append(toText(element, level + 1));
                }
            } else if (obj instanceof List) {
                for (Object element : (List) obj) {
                    if (builder.length() > 0) {
                        builder.appendCodePoint(SEPARATORS[level]);
                    }
                    builder.append(toText(element, level + 1));
                }
            } else {
                builder.append(obj);
            }
            return builder.toString();
        }
    }

    /** Derive the dataType from the {@link Schema.UnresolvedColumn}. */
    public static DataType getType(Schema.UnresolvedColumn column) {
        return (DataType) ((Schema.UnresolvedPhysicalColumn) column).getDataType();
    }
}
