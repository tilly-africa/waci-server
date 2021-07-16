"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.applySocket = exports.sendSocketMessage = void 0;
const ws_1 = __importDefault(require("ws"));
const cookies_1 = require("./cookies");
const webSockets = {};
const sendSocketMessage = (message) => {
    const socket = webSockets[message.token];
    if (typeof socket === 'undefined')
        return;
    return new Promise((resolve, reject) => {
        socket.send(JSON.stringify([message.type, message.payload]), err => {
            if (err)
                reject(err);
            resolve();
        });
    });
};
exports.sendSocketMessage = sendSocketMessage;
const applySocket = (app) => {
    const wss = new ws_1.default.Server({
        server: app.server
    });
    wss.on("connection", (ws, req) => {
        if (req.headers.cookie) {
            const webSocketCookie = app.parseCookie(req.headers.cookie)[cookies_1.webSocketCookieKey];
            if (webSocketCookie) {
                const { valid, value } = app.unsignCookie(webSocketCookie);
                if (valid && typeof value === 'string') {
                    webSockets[value] = ws;
                    return;
                }
            }
        }
        ws.close();
    });
};
exports.applySocket = applySocket;
//# sourceMappingURL=socket.js.map