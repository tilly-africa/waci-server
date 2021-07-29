"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
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
exports.applyCredentialrefRoutes = void 0;
const shared = __importStar(require("@tilly-waci/shared"));
const base64url_1 = __importDefault(require("base64url"));
const verify_1 = require("jose/jwt/verify");
const sign_1 = require("jose/jwt/sign");
const parse_1 = require("jose/jwk/parse");
const uuid_1 = require("uuid");
const did_resolver_1 = require("did-resolver");
const auth_1 = require("@server/auth");
const cookies_1 = require("@server/cookies");
const Credentialrefs_1 = require("@server/entities/Credentialrefs");
const Credentials_1 = require("@server/entities/Credentials");
const UsedTokens_1 = require("@server/entities/UsedTokens");
const waciJose_1 = require("@server/waciJose");
const vc_1 = require("@bloomprotocol/vc");
const ecdsa_secp256k1_verification_key_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-verification-key-2019");
const ecdsa_secp256k1_signature_2019_1 = require("@bloomprotocol/ecdsa-secp256k1-signature-2019");
const base58 = require('base58-universal');
// import { got} from 'got'
// const jsonld = require('jsonld');
const applyCredentialrefRoutes = (app) => {
    // *************************
    // Utils
    // *************************
    const getPublicJwkForKey = (did, keyId, didDoc) => __awaiter(void 0, void 0, void 0, function* () {
        const l = ecdsa_secp256k1_verification_key_2019_1.keyUtils.publicKeyJWKFrom.publicKeyHex(didDoc.publicKey[0]['publicKeyHex'], keyId);
        return l;
    });
    const getResponseTokenKey = (header, token) => __awaiter(void 0, void 0, void 0, function* () {
        if (typeof token.payload !== 'string') {
            throw new Error('Only string payloads are supported');
        }
        const payload = JSON.parse(base64url_1.default.decode(token.payload));
        if (typeof payload.iss !== 'string') {
            throw new Error('No issuer on the payload');
        }
        if (typeof header.kid !== 'string') {
            throw new Error('No keyId on the header');
        }
        if (typeof header.alg !== 'string') {
            throw new Error('No alg on the header');
        }
        const { didDocument } = yield app.resolveDID(payload.iss);
        if (!didDocument) {
            throw new Error('Cannot resolve DID Doc for issuer');
        }
        if (didDocument.id.startsWith('did:elem')) {
            const parsedjwk = yield parse_1.parseJwk(yield getPublicJwkForKey(payload.iss, header.kid, didDocument), header.alg);
            return parsedjwk;
        }
        else {
            throw new Error('Unsupported DID Method');
        }
    });
    const getSuite = ({ verificationMethod, controller, proofType }) => __awaiter(void 0, void 0, void 0, function* () {
        switch (proofType) {
            case 'EcdsaSecp256k1Signature2019':
                if (controller.startsWith('did:elem') && controller.indexOf('elem:initial-state') >= 0) {
                    const { didDocument } = yield app.resolveDID(controller);
                    if (!didDocument)
                        throw new Error(`Could not resolve DID: ${controller}`);
                    const sig = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
                        key: ecdsa_secp256k1_verification_key_2019_1.EcdsaSecp256k1VerificationKey2019.from({
                            controller,
                            id: verificationMethod,
                            publicKeyBase58: base58.encode(Buffer.from(didDocument.publicKey[0]['publicKeyHex'], 'hex')),
                            privateKeyBase58: base58.encode(Buffer.from(didDocument.publicKey[0]['publicKeyHex'], 'hex')),
                        })
                    });
                    return sig;
                }
                return new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019();
            default:
                throw new Error(`Unsupported proofType: ${proofType}`);
        }
    });
    const getProofPurposeOptions = ({ controller, proofPurpose }) => __awaiter(void 0, void 0, void 0, function* () {
        switch (proofPurpose) {
            case 'assertionMethod':
            case 'authentication':
                const { didDocument } = yield app.resolveDID(controller);
                if (controller.startsWith('did:elem') && controller.indexOf('elem:initial-state') >= 0) {
                    return {
                        controller: didDocument,
                    };
                }
                return {};
            default:
                throw new Error(`Unsupported proofPurpose: ${proofPurpose}`);
        }
    });
    // *************************
    // Sign Up
    // *************************
    app.get(shared.api.waci.offer.challengeToken.path, {
        schema: shared.api.waci.offer.challengeToken.schema,
    }, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        const challengeToken = yield new waciJose_1.SignOfferChallengeJWT({
            credential_manifest: {
                id: uuid_1.v4(),
                issuer: {
                    id: app.key.keyPair.controller,
                    name: 'Tilly',
                    styles: {
                        thumbnail: {
                            uri: 'https://tilly.africa/favicon.png',
                            alt: 'Tilly Logo',
                        },
                    },
                },
                output_descriptors: [
                    {
                        id: 'account_output',
                        schema: [
                            {
                                uri: 'https://schema.affinity-project.org/AccountCredentialPersonV1'
                            }
                        ],
                        display: {
                            title: {
                                text: 'Tilly Credential',
                            },
                            description: {
                                text: req.query.credentialref,
                                path: ['$.credentialSubject.@id'],
                            },
                        },
                    },
                ],
            },
            callbackUrl: app.env.waciHost + `${shared.api.waci.offer.submit.path}`,
            credentialref: req.query.credentialref,
            version: '0.1'
        })
            .setProtectedHeader({ alg: 'ES256K', kid: app.key.keyPair.id })
            .setSubject(req.query.token)
            .setJti(uuid_1.v4())
            .setExpirationTime('30m')
            .setIssuer(app.key.keyPair.controller)
            .sign(app.key.keyLike);
        return reply.status(200).send({
            success: true,
            challengeToken
        });
    }));
    app.post(shared.api.waci.offer.submit.path, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        const isUsed = yield UsedTokens_1.isTokenUsed(req.body.responseToken);
        if (isUsed) {
            return reply.status(400).send({
                success: false,
                message: 'Token has already been used'
            });
        }
        let result;
        try {
            result = yield waciJose_1.offerResponseJwtVerify(req.body.responseToken, {
                key: getResponseTokenKey,
            }, {
                key: app.key.keyLike,
                options: {
                    issuer: app.key.keyPair.controller
                }
            });
            const { credentialref, sub } = result.challenge.payload;
            if (typeof credentialref !== 'string')
                throw new Error('Credential ref not set');
            if (typeof sub !== 'string')
                throw new Error('Subject not set');
            if (typeof result.challenge.payload.exp !== 'number')
                throw new Error('Missing exp');
            yield UsedTokens_1.useToken(req.body.responseToken, new Date(result.challenge.payload.exp * 1000));
        }
        catch (e) {
            console.log(e);
            return reply.status(401).send({
                success: false,
                message: 'Response token is not valid'
            });
        }
        const { credentialref } = result.challenge.payload;
        const credentialrefsRepo = Credentialrefs_1.Credentialrefs.getRepo();
        if ((yield credentialrefsRepo.count({ where: { credentialref } })) > 0) {
            return reply.status(400).send({
                success: false,
                message: 'credentialref already exists'
            });
        }
        const Credentialref = new Credentialrefs_1.Credentialrefs();
        Credentialref.credentialref = credentialref;
        const { id: credentialrefId } = yield credentialrefsRepo.save(Credentialref);
        let Credential;
        try {
            Credential = yield Credentials_1.Credentials.getRepo().findOneOrFail({ where: { id: credentialref } });
            Credential.id = 'urn:uuid:' + Credential.id;
        }
        catch (error) {
            return reply.status(400).send({
                success: false,
                message: 'Credential not found in database'
            });
        }
        const unsignedVC = {
            '@context': Credential.context,
            id: Credential.id,
            type: Credential.type,
            issuanceDate: new Date().toISOString(),
            issuer: app.key.keyPair.controller,
            credentialSubject: Credential.credentialSubject,
            holder: { id: result.response.payload.iss }
        };
        const suite = new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
            key: app.key.keyPair
        });
        const credential = yield vc_1.signVC({
            unsigned: unsignedVC,
            suite: suite,
            documentLoader: app.documentLoader,
            addSuiteContext: false
        });
        const unsignedVP = {
            '@context': ['https://www.w3.org/2018/credentials/v1'],
            id: `urn:uuid:${uuid_1.v4()}`,
            type: ['VerifiablePresentation'],
            holder: {
                id: app.key.keyPair.controller
            },
            verifiableCredential: [credential]
        };
        const vp = yield vc_1.signVP({
            unsigned: unsignedVP,
            suite: new ecdsa_secp256k1_signature_2019_1.EcdsaSecp256k1Signature2019({
                key: app.key.keyPair
            }),
            proofPurposeOptions: {
                challenge: uuid_1.v4(),
                domain: 'https://credentials.tilly.africa'
            },
            documentLoader: app.documentLoader,
        });
        let redirectUrl;
        const authToken = yield new sign_1.SignJWT({})
            .setProtectedHeader({ alg: 'ES256K', kid: app.key.keyPair.id })
            .setSubject(credentialrefId)
            .setExpirationTime('30m')
            .setIssuer(app.key.keyPair.controller)
            .sign(app.key.keyLike);
        redirectUrl = `${app.env.waciHost}/authenticate/${authToken}`;
        return reply.status(200).send({
            success: true,
            verifiable_presentation: vp,
            authToken,
            redirectUrl,
        });
    }));
    // *************************
    // Sign In
    // *************************
    app.get(shared.api.waci.request.challengeToken.path, {
        schema: shared.api.waci.request.challengeToken.schema,
    }, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        const challengeToken = yield new waciJose_1.SignRequestChallengeJWT({
            presentation_definition: {
                id: uuid_1.v4(),
                name: 'Tilly Presentation Gateway',
                purpose: "",
                input_descriptors: [
                    {
                        id: 'tilly_vc',
                        name: 'Tilly Verifiable Credential',
                        purpose: 'We need your verified credential',
                        schema: {
                            uri: 'https://schema.affinity-project.org/AccountCredentialPersonV1',
                        },
                        constraints: {
                            fields: [
                                {
                                    path: [`$.type[?(@ == 'AccountCredentialPersonV1')]`],
                                    purpose: `We need need your verifiable credential to have the 'AccountCredentialPersonV1' type.`,
                                    filter: {
                                        type: 'array',
                                    },
                                },
                            ],
                        },
                    }
                ],
            },
            callbackUrl: app.env.waciHost + `${shared.api.waci.request.submit.path}`,
            version: '1'
        })
            .setProtectedHeader({ alg: 'ES256K', kid: app.key.keyPair.id })
            .setSubject(req.query.token)
            .setJti(uuid_1.v4())
            .setExpirationTime('30m')
            .setIssuer(app.key.keyPair.controller)
            .sign(app.key.keyLike);
        return reply.status(200).send({
            success: true,
            challengeToken,
        });
    }));
    app.post(shared.api.waci.request.submit.path, {
        schema: shared.api.waci.request.submit.schema,
    }, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        var _a, _b;
        const isUsed = yield UsedTokens_1.isTokenUsed(req.body.responseToken);
        if (isUsed) {
            return reply.status(400).send({
                success: false,
                message: 'Token has already been used'
            });
        }
        let result;
        try {
            result = yield waciJose_1.requestResponseJwtVerify(req.body.responseToken, {
                key: getResponseTokenKey,
            }, {
                key: app.key.keyLike,
                options: {
                    issuer: app.key.keyPair.controller
                }
            });
            const { sub } = result.challenge.payload;
            if (typeof sub !== 'string')
                throw new Error('Subject not set');
            if (typeof result.challenge.payload.exp !== 'number')
                throw new Error('Missing exp');
            yield UsedTokens_1.useToken(req.body.responseToken, new Date(result.challenge.payload.exp * 1000));
        }
        catch (e) {
            console.log(e);
            return reply.status(401).send({
                success: false,
                message: 'Response token is not valid'
            });
        }
        const presentation = result.response.payload['verifiable_presentation'];
        const validationResult = yield vc_1.verifyVP({
            vp: presentation,
            getSuite: getSuite,
            documentLoader: app.documentLoader,
            getProofPurposeOptions: getProofPurposeOptions,
        });
        if (validationResult.success === false) {
            console.log(JSON.stringify(validationResult));
            return reply.status(400).send({
                success: false,
                message: 'Invalid Presentation Submission'
            });
        }
        let credentialrefId;
        try {
            const credential = validationResult.vp.verifiableCredential[0];
            const issuerDid = (_a = did_resolver_1.parse(credential.issuer)) === null || _a === void 0 ? void 0 : _a.did;
            const ourDid = (_b = did_resolver_1.parse(app.key.keyPair.controller)) === null || _b === void 0 ? void 0 : _b.did;
            if (!issuerDid || !ourDid || issuerDid !== ourDid) {
                throw new Error('Not issued by Tilly');
            }
            const credentialref = credential.credentialSubject['id'].replace('urn:uuid:', '');
            const Credentialref = yield Credentialrefs_1.Credentialrefs.getRepo().findOneOrFail({ where: { credentialref } });
            credentialrefId = Credentialref.id;
        }
        catch (_c) {
            return reply.status(400).send({
                success: false,
                message: 'Account credential not found in submission'
            });
        }
        const authToken = yield new sign_1.SignJWT({})
            .setProtectedHeader({ alg: 'ES256K', kid: app.key.keyPair.id })
            .setSubject(credentialrefId)
            .setExpirationTime('30m')
            .setIssuer(app.key.keyPair.controller)
            .sign(app.key.keyLike);
        let redirectUrl;
        redirectUrl = `${app.env.waciHost}/authenticate/${authToken}`;
        return reply.status(200).send({
            success: true,
            authToken,
            redirectUrl,
        });
    }));
    app.post(shared.api.waci.request.authenticate.path, {
        schema: shared.api.waci.request.authenticate.schema,
    }, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        const isUsed = yield UsedTokens_1.isTokenUsed(req.body.token);
        if (isUsed) {
            return reply.status(400).send({
                success: false,
                message: 'Token has already been used'
            });
        }
        let result;
        try {
            result = yield verify_1.jwtVerify(req.body.token, app.key.keyLike, { issuer: app.key.keyPair.controller });
            if (typeof result.payload.exp !== 'number')
                throw new Error('Expiration not set');
            if (typeof result.payload.sub === 'undefined')
                throw new Error('Subject not set');
            yield UsedTokens_1.useToken(req.body.token, new Date(result.payload.exp * 1000));
        }
        catch (_d) {
            return cookies_1.clearWebSocketCookie(reply).status(400).send({
                success: false,
                message: 'Token is invalid'
            });
        }
        return cookies_1.setCredentialrefCookie(reply, result.payload.sub).status(200).send({
            success: true
        });
    }));
    // *************************
    // Available
    // *************************
    app.post(shared.api.waci.available.path, {
        schema: shared.api.waci.available.schema,
    }, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        const count = yield Credentialrefs_1.Credentialrefs.getRepo().count({ where: { credentialref: req.body.credentialref } });
        return reply.status(200).send({
            available: count >= 1 ? false : true,
            success: true,
        });
    }));
    // *************************
    // Me
    // *************************
    app.get(shared.api.waci.me.path, {
        schema: shared.api.waci.me.schema,
        preHandler: app.auth([auth_1.verifyCredentialref]),
    }, (req, reply) => __awaiter(void 0, void 0, void 0, function* () {
        const credentialref = auth_1.getCredentialref(req);
        return reply.status(200).send({
            credentialref: credentialref.toView(),
            success: true,
        });
    }));
    // *************************
    // Log Out
    // *************************
    app.get(shared.api.waci.logOut.path, {
        schema: shared.api.waci.logOut.schema,
    }, (_, reply) => __awaiter(void 0, void 0, void 0, function* () {
        cookies_1.clearCredentialrefCookie(reply);
        cookies_1.clearWebSocketCookie(reply);
        return reply.status(200).send({
            success: true
        });
    }));
};
exports.applyCredentialrefRoutes = applyCredentialrefRoutes;
//# sourceMappingURL=credentialrefs.js.map