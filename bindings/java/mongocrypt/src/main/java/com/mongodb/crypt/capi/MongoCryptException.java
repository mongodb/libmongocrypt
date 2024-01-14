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

package com.mongodb.crypt.capi;


/**
 * Top level Exception for all Mongo Crypt CAPI exceptions
 */
public class MongoCryptException extends RuntimeException {
    private static final long serialVersionUID = -5524416583514807953L;
    private final int code;

    /**
     * @param msg the message
     */
    public MongoCryptException(final String msg) {
        super(msg);
        this.code = -1;
    }

    /**
     * @param msg   the message
     * @param cause the cause
     */
    public MongoCryptException(final String msg, Throwable cause) {
        super(msg, cause);
        this.code = -1;
    }

    public MongoCryptException(final String msg, final int code) {
        super(msg);
        this.code = code;
    }

    /**
     * @return the error code for the exception.
     */
    public int getCode() {
        return code;
    }
}
