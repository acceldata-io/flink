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

import org.apache.flink.configuration.ConfigOption;
import org.apache.flink.table.catalog.CatalogTable;
import org.apache.flink.table.catalog.hive.HiveCatalog;
import org.apache.flink.table.connector.sink.DynamicTableSink;
import org.apache.flink.table.connector.source.DynamicTableSource;
import org.apache.flink.table.factories.DynamicTableSinkFactory;
import org.apache.flink.table.factories.DynamicTableSourceFactory;
import org.apache.flink.table.factories.FactoryUtil;

import java.util.Collections;
import java.util.Set;

import static org.apache.flink.util.Preconditions.checkNotNull;

/** A table factory implementation for Hive catalog. */
public class HiveTableFactory implements DynamicTableSourceFactory, DynamicTableSinkFactory {
    @Override
    public DynamicTableSink createDynamicTableSink(Context context) {
        CatalogTable table = checkNotNull(context.getCatalogTable());

        boolean isHiveTable = HiveCatalog.isHiveTable(table.getOptions());

        // we don't support temporary hive tables yet
        if (isHiveTable && !context.isTemporary()) {
            throw new UnsupportedOperationException(
                    "Legacy TableSink for Hive is deprecated. Hive table sink should be created by HiveDynamicTableFactory.");
        } else {
            return FactoryUtil.createDynamicTableSink(
                    null,
                    context.getObjectIdentifier(),
                    context.getCatalogTable(),
                    context.getEnrichmentOptions(),
                    context.getConfiguration(),
                    context.getClassLoader(),
                    context.isTemporary());
        }
    }

    @Override
    public DynamicTableSource createDynamicTableSource(Context context) {
        CatalogTable table = checkNotNull(context.getCatalogTable());

        boolean isHiveTable = HiveCatalog.isHiveTable(table.getOptions());

        // we don't support temporary hive tables yet
        if (isHiveTable && !context.isTemporary()) {
            throw new UnsupportedOperationException(
                    "Legacy TableSource for Hive is deprecated. Hive table source should be created by HiveDynamicTableFactory.");
        } else {
            return FactoryUtil.createDynamicTableSource(
                    null,
                    context.getObjectIdentifier(),
                    context.getCatalogTable(),
                    context.getEnrichmentOptions(),
                    context.getConfiguration(),
                    context.getClassLoader(),
                    context.isTemporary());
        }
    }

    @Override
    public String factoryIdentifier() {
        return "hive";
    }

    @Override
    public Set<ConfigOption<?>> requiredOptions() {
        return Collections.emptySet();
    }

    @Override
    public Set<ConfigOption<?>> optionalOptions() {
        return Collections.emptySet();
    }
}
