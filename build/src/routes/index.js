"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.routes = void 0;
const did_1 = require("./did");
const credentialrefs_1 = require("./credentialrefs");
const websocket_1 = require("./websocket");
const routes = (app, _, done) => {
    did_1.applyDIDRoutes(app);
    credentialrefs_1.applyCredentialrefRoutes(app);
    websocket_1.applyWebsocketRoutes(app);
    done();
};
exports.routes = routes;
//# sourceMappingURL=index.js.map