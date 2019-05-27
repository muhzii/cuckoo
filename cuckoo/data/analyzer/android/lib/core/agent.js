// Copyright (C) 2019 Cuckoo Foundation.
// This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
// See the file 'docs/LICENSE' for copying permission.

'use strict';

/** 
 * Exposed methods for the Frida client.
 */
function Api () {

    this.readBytes = function(address, size) {
        return ptr(address).readByteArray(size);
    };

    this.enumerateRanges = function(protection) {
        return Process.enumerateRanges(protection)
    };
};

/** 
 * Monitor all the Java methods specified in the config object.
 * @param {Object} hooksConfig - configuration object for JVM hooks.
 * @param {Boolean} preload - Specifies whether or not to wait for
 * the application's class loader to be available.
 */
function monitorJavaMethods (hooksConfig, preload) {
    for (let className in hooksConfig) {
        if (hooksConfig.hasOwnProperty(className)) {
            hooksConfig[className].forEach(methodConfig => {
                let callback = function() {
                    monitorJavaMethod(className, methodConfig);
                };

                if (preload) {
                    Java.performNow(callback);
                } else {
                    Java.perform(callback);
                }
            });
        }
    }
};

/** 
 * Replace a method's implementation using the configuration object.
 * Needs to be called from a thread attached to the VM..
 */
function monitorJavaMethod (className, methodConfig) {
    try {
        const klass = Java.use(className);
        const methodName = methodConfig.name;
        const overloads = klass[methodName].overloads;

        overloads.forEach(method => {
            method.implementation = function() {
                // Data object sent back to the client..
                let hookData = {
                    "category": methodConfig.category,
                    "class": className,
                    "method": methodName
                }
                
                let capturedArguments = {}
                if (methodConfig.hasOwnProperty("captureArguments")) {
                    capturedArguments = methodConfig.captureArguments;
                }
                for (let argNumber in capturedArguments) {
                    if (capturedArguments.hasOwnProperty(argNumber)) {
                        argNumber = parseInt(argNumber);
                        if (isNaN(argNumber)) {
                            continue;
                        }

                        let argValue = null;
                        if (argNumber < arguments.length) {
                            argValue = getJavaObjectValue(arguments[argNumber]);
                        }

                        if (argValue !== null) {
                            hookData[capturedArguments[argNumber]] = argValue;
                        }  
                    }
                }

                let capturedAttributes = {}
                if (methodConfig.hasOwnProperty("captureAttributes")) {
                    capturedAttributes = methodConfig.captureAttributes;
                }
                for (let attributeName in capturedAttributes) {
                    if (capturedAttributes.hasOwnProperty(attributeName)) {
                        let nestedAttributes = attributeName.split(".");

                        let wrapper = this;
                        for (let i = 0; i < nestedAttributes.length; i++) {
                            let isMethod = false;
                            let subAttributeName = nestedAttributes[i];
                            if (nestedAttributes[i].endsWith("()")) {
                                isMethod = true;
                                subAttributeName = subAttributeName.slice(0, -2);
                            }

                            if (!isMethod) {
                                wrapper = wrapper[subAttributeName].value;
                            } else {
                                wrapper = wrapper[subAttributeName]();
                            } 
                        }

                        let value = getJavaObjectValue(wrapper);
                        if (value !== null) {
                            hookData[capturedAttributes[attributeName]] = value;
                        }
                    }
                }

                LOG("jvmHook", hookData);

                return method.apply(this, arguments);
            };
        });
    } catch(e) {
        setTimeout(() => { throw e; }, 0);
    }
};

/** 
 * Extracts the value of an object returned from the Java runtime.
 */
function getJavaObjectValue (obj) {
    if (obj === null) {
        return null;
    }

    const Arrays = Java.use("java.util.Arrays");
    const String = Java.use("java.lang.String");

    const javaType = obj.hasOwnProperty('$className')? obj.$className: null;

    if (javaType !== null) { // unboxed value
        // Ensure type casting ..
        const klass = Java.use(javaType);
        let castedObj = Java.cast(obj, klass);

        if (javaType == "java.io.File") {
            return castedObj.getAbsolutePath();
        } else if (javaType == "android.content.ContentValues") {
            let keys = castedObj.keySet();
            var result = [];

            for (let i = 0; i < keys.size(); i++) {
                let key = keys.iterator().next();
                result.push({
                    "Key": key.toString(),
                    "Value": castedObj.get(key).toString()
                });
            }
            return result;
        } else {
            // unbox the string representation..
            return castedObj.toString();
        }
    } else if (typeof obj === "string" || 
               typeof obj === "number" ||
               typeof obj === "boolean") {
        return obj;
    } else if (Array.isArray(obj)) { // non-primitive array
        return Arrays.deepToString(obj);
    } else if (obj.type === "byte") { // primitive array
        return String.$new(obj).toString();
    } else {
        return null;
    }
};

/** 
 * Utility method for forwarding messages to Frida's client..
 * @param {String} subsys - source of message.
 * @param {*} message - the message.
 */
function LOG (subsys, message) {
    if (typeof message === "object") {
        message = JSON.stringify(message);
    }

    send(subsys + ":" + message);
};

var api = new Api();

rpc.exports = {
    api: function(api_method, args) {
        return api[api_method].apply(this, args);
    },
    start: function(configs) {
        if (Java.available) {
            monitorJavaMethods(configs["jvm_hooks"], true);
        }
    }
};
