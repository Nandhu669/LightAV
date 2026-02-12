"use strict";

var QWebChannelMessageTypes = {
    signal: 1,
    propertyUpdate: 2,
    init: 3,
    idle: 4,
    debug: 5,
    invokeMethod: 6,
    connectToSignal: 7,
    disconnectFromSignal: 8,
    setProperty: 9,
    response: 10
};

export var QWebChannel = function (transport, initCallback) {
    if (typeof transport !== "object" || typeof transport.send !== "function") {
        console.error("The QWebChannel requires a transport object. This object must implement a send() function.");
        return;
    }

    var channel = this;
    this.transport = transport;

    this.send = function (data) {
        if (typeof data !== "string") {
            data = JSON.stringify(data);
        }
        channel.transport.send(data);
    }

    this.transport.onmessage = function (message) {
        var data = message.data;
        if (typeof data === "string") {
            data = JSON.parse(data);
        }
        switch (data.type) {
            case QWebChannelMessageTypes.signal:
                channel.handleSignal(data);
                break;
            case QWebChannelMessageTypes.response:
                channel.handleResponse(data);
                break;
            case QWebChannelMessageTypes.propertyUpdate:
                channel.handlePropertyUpdate(data);
                break;
            default:
                console.error("invalid message received:", message.data);
                break;
        }
    }

    this.execCallbacks = {};
    this.execId = 0;
    this.exec = function (data, callback) {
        var id = channel.execId++;
        if (callback) {
            channel.execCallbacks[id] = callback;
        }
        data.id = id;
        channel.send(data);
    };

    this.objects = {};

    this.handleSignal = function (message) {
        var object = channel.objects[message.object];
        if (object) {
            object.signalEmitted(message.signal, message.args);
        } else {
            console.warn("Unhandled signal: " + message.object + "::" + message.signal);
        }
    }

    this.handleResponse = function (message) {
        if (!message.hasOwnProperty("id")) {
            console.error("Invalid response message received: ", JSON.stringify(message));
            return;
        }
        if (channel.execCallbacks[message.id]) {
            channel.execCallbacks[message.id](message.data);
            delete channel.execCallbacks[message.id];
        }
    }

    this.handlePropertyUpdate = function (message) {
        for (var i in message.signals) {
            var signal = message.signals[i];
            var object = channel.objects[signal[0]];
            if (object) {
                object.signalEmitted(signal[1], signal[2]);
            } else {
                console.warn("Unhandled signal: " + signal[0] + "::" + signal[1]);
            }
        }
        for (var i in message.properties) {
            var property = message.properties[i];
            var object = channel.objects[property[0]];
            if (object) {
                object.propertyUpdate(property[1], property[2]);
            } else {
                console.warn("Unhandled property update: " + property[0] + "::" + property[1]);
            }
        }
    }

    this.debug = function (message) {
        channel.send({ type: QWebChannelMessageTypes.debug, data: message });
    };

    this.exec({ type: QWebChannelMessageTypes.init }, function (data) {
        for (var objectName in data) {
            var objectpath = objectName.split(".");
            var object = new QObject(objectName, data[objectName], channel);
            var parent = channel.objects;
            for (var i = 0; i < objectpath.length - 1; ++i) {
                if (!parent[objectpath[i]]) {
                    parent[objectpath[i]] = {};
                }
                parent = parent[objectpath[i]];
            }
            parent[objectpath[objectpath.length - 1]] = object;
        }

        for (var objectName in channel.objects) {
            channel.objects[objectName].unwrappedProperties();
        }

        if (initCallback) {
            initCallback(channel);
        }
        channel.debug("connected to QWebChannel.");
    });
};

function QObject(name, data, webChannel) {
    this.__id__ = name;
    webChannel.objects[name] = this;
    this.__objectSignals__ = {};
    this.__unwrappedProperties__ = {};

    var self = this;

    this.unwrappedProperties = function () {
        return self.__unwrappedProperties__;
    };

    this.propertyUpdate = function (propertyName, propertyValue) {
        self[propertyName] = propertyValue;
        var signalName = propertyName + "Changed";
        if (self[signalName]) {
            self[signalName].emit(propertyValue);
        }
    };

    this.signalEmitted = function (signalName, signalArgs) {
        var handlers = self.__objectSignals__[signalName];
        if (handlers) {
            for (var i in handlers) {
                handlers[i].callback.apply(self, signalArgs);
            }
        }
    };

    this.addSignalHandler = function (signalName, callback) {
        if (!self.__objectSignals__[signalName]) {
            self.__objectSignals__[signalName] = [];
        }
        self.__objectSignals__[signalName].push({ callback: callback });
        if (webChannel) {
            webChannel.exec({
                type: QWebChannelMessageTypes.connectToSignal,
                object: self.__id__,
                signal: signalName
            });
        }
    };

    this.removeSignalHandler = function (signalName, callback) {
        var handlers = self.__objectSignals__[signalName];
        if (!handlers) {
            return;
        }
        for (var i = 0; i < handlers.length; ++i) {
            if (handlers[i].callback === callback) {
                handlers.splice(i, 1);
                break;
            }
        }
        if (handlers.length === 0 && webChannel) {
            webChannel.exec({
                type: QWebChannelMessageTypes.disconnectFromSignal,
                object: self.__id__,
                signal: signalName
            });
        }
    };

    for (var i in data.methods) {
        var methodName = data.methods[i][0];
        this[methodName] = (function (methodName) {
            return function () {
                var args = [];
                var callback;
                for (var i = 0; i < arguments.length; ++i) {
                    if (typeof arguments[i] === "function") {
                        callback = arguments[i];
                    } else {
                        args.push(arguments[i]);
                    }
                }

                webChannel.exec({
                    type: QWebChannelMessageTypes.invokeMethod,
                    object: self.__id__,
                    method: methodName,
                    args: args
                }, callback);
            };
        })(methodName);
    }

    for (var signalName in data.signals) {
        this[signalName] = (function (signalName) {
            return {
                connect: function (callback) {
                    self.addSignalHandler(signalName, callback);
                },
                disconnect: function (callback) {
                    self.removeSignalHandler(signalName, callback);
                }
            };
        })(signalName);
    }

    for (var propertyName in data.properties) {
        this[propertyName] = data.properties[propertyName][2];
        this.__unwrappedProperties__[propertyName] = data.properties[propertyName][2];
        this[propertyName + "Changed"] = (function (propertyName) {
            return {
                connect: function (callback) {
                    self.addSignalHandler(propertyName + "Changed", callback);
                },
                disconnect: function (callback) {
                    self.removeSignalHandler(propertyName + "Changed", callback);
                }
            };
        })(propertyName);
    }
}
