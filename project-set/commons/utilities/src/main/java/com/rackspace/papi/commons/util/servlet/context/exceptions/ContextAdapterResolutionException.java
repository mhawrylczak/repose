/*
 *  Copyright 2010 Rackspace.
 * 
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 */
package com.rackspace.papi.commons.util.servlet.context.exceptions;

/**
 *
 * 
 */
public class ContextAdapterResolutionException extends RuntimeException {

    public ContextAdapterResolutionException(String message, Throwable cause) {
        super(message, cause);
    }

    public ContextAdapterResolutionException(String message) {
        super(message);
    }
}
