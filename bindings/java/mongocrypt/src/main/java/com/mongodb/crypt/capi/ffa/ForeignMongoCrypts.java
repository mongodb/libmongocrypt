/*
 * Copyright 2019-present MongoDB, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.mongodb.crypt.capi.ffa;

import com.mongodb.crypt.capi.MongoCrypt;
import com.mongodb.crypt.capi.MongoCryptOptions;

/**
 * The entry point to the MongoCrypt library.
 */
public class ForeignMongoCrypts {

    /**
     * Create a {@code MongoCrypt} instance.
     *
     * @param options the options
     * @return the instance
     */
    public static MongoCrypt create(MongoCryptOptions options) {
        return new ForeignMongoCrypt(options);
    }
}
