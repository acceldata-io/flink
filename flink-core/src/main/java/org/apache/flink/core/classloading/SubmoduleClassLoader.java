/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.flink.core.classloading;

import org.apache.flink.configuration.CoreOptions;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

/**
 * Loads all classes from the submodule jar, except for explicitly white-listed packages.
 *
 * <p>To ensure that classes from the submodule are always loaded through the submodule classloader
 * (and thus from the submodule jar), even if the classes are also on the classpath (e.g., during
 * tests), all classes from the "org.apache.flink" package are loaded child-first.
 *
 * <p>Classes related to logging (e.g., log4j) are loaded parent-first.
 *
 * <p>Shaded third-party libraries under {@code org.apache.flink.shaded.} are forced parent-first —
 * submodule jars (e.g. flink-rpc-akka.jar, flink-table-planner.jar) bundle their own copy of these
 * shaded libs (netty4, jackson2, guava33, …) which overlap with flink-dist's copy on the owner
 * (app) loader. Loading the submodule's copy child-first produced duplicate Class objects for the
 * same shaded prefix across the two loaders and crashed TaskManager startup with: {@code
 * LinkageError: loader constraint violation ... Bootstrap/AddressResolverGroup} {@code
 * IncompatibleClassChangeError: LengthFieldPrepender does not implement ChannelHandler}. Longest
 * matching prefix wins in {@link ComponentClassLoader}'s matcher (owner-first entry {@code
 * org.apache.flink.shaded.} outscores the broader component-first entry {@code org.apache.flink}),
 * so these classes delegate to the owner loader.
 *
 * <p>All other classes can only be loaded if they are either available in the submodule jar or the
 * bootstrap/app classloader (i.e., provided by the JDK).
 */
public class SubmoduleClassLoader extends ComponentClassLoader {

    private static final String[] OWNER_FIRST_PACKAGES =
            concat(
                    CoreOptions.PARENT_FIRST_LOGGING_PATTERNS,
                    new String[] {"org.apache.flink.shaded."});

    public SubmoduleClassLoader(URL[] classpath, ClassLoader parentClassLoader) {
        super(
                classpath,
                parentClassLoader,
                OWNER_FIRST_PACKAGES,
                new String[] {"org.apache.flink"},
                Collections.emptyMap());
    }

    private static String[] concat(String[] a, String[] b) {
        String[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
}
