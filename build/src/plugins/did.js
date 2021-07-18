"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.didPlugin = void 0;
const fastify_plugin_1 = __importDefault(require("fastify-plugin"));
const parse_1 = require("jose/jwk/parse");
const ecdsa_secp256k1_verification_key_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-verification-key-2019");
const elem_did_legacy_non_anchored_1 = require("@bloomprotocol/elem-did-legacy-non-anchored");
const did_resolver_1 = require("did-resolver");
const base58 = require('base58-universal');
const jsonld = require('jsonld');
const pluginCallback = (fastify, { controller, id, publicKeyHex, privateKeyHex }, done) => __awaiter(void 0, void 0, void 0, function* () {
    const keyPair = new ecdsa_secp256k1_verification_key_2019_1.EcdsaSecp256k1VerificationKey2019({
        publicKeyBase58: base58.encode(Buffer.from(publicKeyHex, 'hex')),
        privateKeyBase58: base58.encode(Buffer.from(privateKeyHex, 'hex')),
        id: id,
        controller: controller,
        revoked: false
    });
    const resolveDID = (did) => {
        return new did_resolver_1.Resolver(elem_did_legacy_non_anchored_1.resolverRegistry).resolve(did);
    };
    const documentLoader = (url) => __awaiter(void 0, void 0, void 0, function* () {
        if (url.startsWith('did:')) {
            const { didDocument } = yield resolveDID(url);
            return {
                contextUrl: null,
                document: didDocument,
                documentUrl: url,
            };
        }
        return jsonld.documentLoaders.node()(url);
    });
    fastify.decorate('documentLoader', documentLoader);
    fastify.decorate('resolveDID', resolveDID);
    fastify.decorate('key', {
        keyPair,
        keyLike: yield parse_1.parseJwk(ecdsa_secp256k1_verification_key_2019_1.keyUtils.privateKeyJWKFrom.privateKeyBase58(keyPair.privateKeyBase58, id), 'ES256K')
    });
    done();
});
exports.didPlugin = fastify_plugin_1.default(pluginCallback, '3.x');
//# sourceMappingURL=did.js.map