import { JsonWebKey, JsonWebSignature as  JsonWebSignatureBase, JsonWebSignatureOptions} from '@transmute/json-web-signature';
import { buildVCV1, buildVCV1Skeleton, buildVCV1Unsigned, buildVPV1, buildVPV1Unsigned, validateVPV1 } from '@affinidi/vc-common';
// import { base58  } from '@transmute/ed25519-key-pair/src/encoding'

import { FastifyInstance } from 'fastify'
import * as shared from '@tilly-waci/shared'
import base64url from 'base64url';
import { jwtVerify, JWTVerifyGetKey } from 'jose/jwt/verify';
import { SignJWT } from 'jose/jwt/sign';
import { parseJwk } from 'jose/jwk/parse';
import { JWTPayload } from 'jose/types';
import { v4 as uuid } from 'uuid'
import {VCAccountPersonV1 } from '@affinidi/vc-data';

import { DIDDocument, parse } from 'did-resolver'
import * as ed25519 from '@transmute/did-key-ed25519';
import * as x25519 from '@transmute/did-key-x25519';
import * as bls12381 from '@transmute/did-key-bls12381';
import * as secp256k1 from '@transmute/did-key-secp256k1';
import * as webCrypto from '@transmute/did-key-web-crypto';

import { verifyCredentialref, getCredentialref } from '@server/auth'
import { clearCredentialrefCookie, clearWebSocketCookie, setCredentialrefCookie } from '@server/cookies'
import { Credentialrefs } from '@server/entities/Credentialrefs'
import { Credentials } from '@server/entities/Credentials'

import { isTokenUsed, useToken } from '@server/entities/UsedTokens';
import { SignOfferChallengeJWT, offerResponseJwtVerify, SignRequestChallengeJWT, requestResponseJwtVerify } from '@server/waciJose'


class JsonWebSignature extends JsonWebSignatureBase {
  constructor(options?: JsonWebSignatureOptions) {
    super(options)
    this.type = 'JsonWebSignature2020'
  }

  async matchProof({proof}: any) {
    return proof.type === 'https://w3id.org/security#JsonWebSignature2020' || proof.type === 'JsonWebSignature2020';
  }

  async verifySignature({ verifyData, verificationMethod, proof }: any) {
    return true;
    // let { verifier }: any = this;

    // if (!verifier) {
    //   const key = await JsonWebKey.from(verificationMethod);
    //   verifier = key.verifier();
    // //   const key = await webCrypto.WebCryptoKey.from(verificationMethod);
    // //   const j = await key.export({ type: 'JsonWebKey2020'})

    // //  verifier = await webKp.jws.getDetachedJwsVerifier(
    // //     await webKp.key.getCryptoKeyFromJsonWebKey2020({
    // //       publicKeyJwk:j['publicKeyJwk'],
    // //     })
    // //   );
    // }
    // return verifier.verify({ data: verifyData, signature: proof.jws });
  }
}

export const applyCredentialrefRoutes = (app: FastifyInstance): void => {
  // *************************
  // Utils
  // *************************

  const getPublicJwkForKey = async (did: string, keyId: string, didDoc: DIDDocument) => {
    const idchar: any = did.split('did:key:').pop();
    const encodedType = idchar.substring(0, 4);

    const verificationMethod = didDoc.verificationMethod?.find(({id}) => keyId.includes(id))

    if (typeof verificationMethod === 'undefined') {
      throw new Error('Could not find publicKey for given keyId')
    }

    if (typeof verificationMethod.publicKeyBase58 === 'undefined') {
      throw new Error('Could not find publicKey for given keyId')
    }

    switch (encodedType) {
      case 'z6Mk':
        return ed25519.Ed25519KeyPair.fromFingerprint({fingerprint: idchar}).toJwk()
      case 'z6LS':
        return x25519.X25519KeyPair.fromFingerprint({fingerprint: idchar})
      case 'zUC7':
        return (await bls12381.Bls12381G2KeyPair.fromFingerprint({fingerprint: idchar})).toJsonWebKeyPair().publicKeyJwk
      case 'z3tE':
        return (await bls12381.Bls12381G1KeyPair.fromFingerprint({fingerprint: idchar})).toJsonWebKeyPair().publicKeyJwk
      case 'z5Tc':
        throw new Error('Unsupported encoding type')
      case 'zQ3s':
        return secp256k1.Secp256k1KeyPair.fromFingerprint({fingerprint: idchar}).toJwk()
      case 'zDna':
      case 'z82L':
      case 'z2J9':
      case 'zXwp':
      case 'zACH':
      case 'zJss':
        const k = await webCrypto.WebCryptoKey.fromFingerprint({fingerprint: idchar})
        const j = await k.export({ type: 'JsonWebKey2020'})
        return j['publicKeyJwk']
      default:
        throw new Error('Unsupported encoding type' + encodedType)
    }
  }

  const getResponseTokenKey: JWTVerifyGetKey = async (header, token) => {
    if (typeof token.payload !== 'string') {
      throw new Error('Only string payloads are supported')
    }

    const payload: JWTPayload = JSON.parse(base64url.decode(token.payload))

    if (typeof payload.iss !== 'string') {
      throw new Error('No issuer on the payload')
    }
    if (typeof header.kid !== 'string') {
      throw new Error('No keyId on the header')
    }
    if (typeof header.alg !== 'string') {
      throw new Error('No alg on the header')
    }

    const {didDocument} = await app.resolveDID(payload.iss)

    if (!didDocument) {
      throw new Error('Cannot resolve DID Doc for issuer')
    }

    if (didDocument.id.startsWith('did:key')) { 
      const parsedjwk = await parseJwk(await getPublicJwkForKey(payload.iss, header.kid, didDocument), header.alg)
      return parsedjwk
    } else {
      throw new Error('Unsupported DID Method')
    }
  }

  // *************************
  // Sign Up
  // *************************

  app.get<shared.api.waci.offer.challengeToken.RouteInterface>(
    shared.api.waci.offer.challengeToken.path,
    {
      schema: shared.api.waci.offer.challengeToken.schema,
    },
    async (req, reply) => {
      const challengeToken = await new SignOfferChallengeJWT({
        credential_manifest: {
          id: uuid(),
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
                  path: ['$.credentialSubject.data.hasAccount.identifier'],
                },
              },
            },
          ],
        },
        callbackUrl: app.env.waciHost + `${shared.api.waci.offer.submit.path}`,
        credentialref: req.query.credentialref,
        version: '0.1' as any
      })
        .setProtectedHeader({alg: 'EdDSA', kid: app.key.keyPair.id})
        .setSubject(req.query.token)
        .setJti(uuid())
        .setExpirationTime('30m')
        .setIssuer(app.key.keyPair.controller)
        .sign(app.key.keyLike)

      return reply.status(200).send({
        success: true,
        challengeToken
      })
    },
  )

  app.post<shared.api.waci.offer.submit.RouteInterface>(
    shared.api.waci.offer.submit.path,
    {
      schema: shared.api.waci.offer.submit.schema,
    },
    async (req, reply) => {
      const isUsed = await isTokenUsed(req.body.responseToken)

      if (isUsed) {
        return reply.status(400).send({
          success: false,
          message: 'Token has already been used'
        })
      }

      let result

      try {
        result = await offerResponseJwtVerify(
          req.body.responseToken,
          {
            key: getResponseTokenKey,
          },
          {
            key: app.key.keyLike,
            options: {
              issuer: app.key.keyPair.controller
            }
          }
        )

        const {credentialref, sub} = result.challenge.payload

        if (typeof credentialref !== 'string') throw new Error('Credential ref not set')
        if (typeof sub !== 'string') throw new Error('Subject not set')
        if (typeof result.challenge.payload.exp !== 'number') throw new Error('Missing exp')

        await useToken(req.body.responseToken, new Date(result.challenge.payload.exp * 1000))
      } catch(e) {
        console.log(e)
        return reply.status(401).send({
          success: false,
          message: 'Response token is not valid'
        })
      }

      const {credentialref, credential_manifest } = result.challenge.payload

      const credentialrefsRepo = Credentialrefs.getRepo()

      if ((await credentialrefsRepo.count({where: {credentialref}})) > 0) {
        return reply.status(400).send({
          success: false,
          message: 'credentialref already exists'
        })
      }

      const Credentialref = new Credentialrefs()
      Credentialref.credentialref = credentialref as string
      const {id: credentialrefId} = await credentialrefsRepo.save(Credentialref)
      let Credential;
      try {
       Credential = await Credentials.getRepo().findOneOrFail({where: {id: credentialref}})
       Credential.id = 'urn:uuid:' + Credential.id;
      } catch (error) {
        return reply.status(400).send({
          success: false,
          message: 'Credential not found in database'
        })
      }

      const credential = await buildVCV1({
        unsigned: buildVCV1Unsigned({
          skeleton: buildVCV1Skeleton({
            context: Credential.context, 
            holder: Credential.holder,
            credentialSubject: Credential.credentialSubject,
            type: Credential.type,
            id: Credential.id
          }),
          issuanceDate: new Date().toISOString()
        }),
        issuer: {
          did: app.key.keyPair.controller,
          keyId: app.key.keyPair.id,
          privateKey: '',
        },
        getSignSuite: async () => {
          return new JsonWebSignature({
            key: await JsonWebKey.from(app.key.keyPair.toJsonWebKeyPair(true)),
          });
        },
        documentLoader: app.documentLoader,
      })

      const unsignedVP = {
        ...buildVPV1Unsigned({
          id: `urn:uuid:${uuid()}`,
          vcs: [credential],
          holder: {
            id: result.response.payload.iss!
          },
          context: [
            'https://w3id.org/security/jws/v1',
            {
              '@version': 1.1,
              CredentialFulfillment: {
                '@id':
                  'https://identity.foundation/credential-manifest/#credential-fulfillment',
                '@type': '@id',
                '@context': {
                  '@version': 1.1,
                  credential_fulfillment: {
                    '@id':
                      'https://identity.foundation/credential-manifest/#credential-fulfillment',
                    '@type': '@json',
                  },
                },
              },
            }
          ],
          type: 'CredentialFulfillment',
        }),
        credential_fulfillment: {
          id: uuid(),
          manifest_id: (credential_manifest as any).id,
          descriptor_map: [
            {
              id: 'account_output',
              format: 'ldp_vc',
              path: '$.verifiableCredential[0]'
            }
          ],
        },
      }
      const jsw = new JsonWebSignature({
        key: await JsonWebKey.from(app.key.keyPair.toJsonWebKeyPair(true)),
      })

      const vp = await buildVPV1({
        unsigned: unsignedVP,
        holder: {
          did: app.key.keyPair.controller,
          keyId: app.key.keyPair.id,
          privateKey: '',
        },
        getSignSuite: async () => jsw,
        documentLoader: app.documentLoader,
        getProofPurposeOptions: () => ({
          challenge: uuid(),
          domain: 'https://credentials.tilly.africa'
        })
      })

      let redirectUrl: string | undefined

      const authToken = await new SignJWT({})
        .setProtectedHeader({alg: 'EdDSA', kid: app.key.keyPair.id})
        .setSubject(credentialrefId)
        .setExpirationTime('30m')
        .setIssuer(app.key.keyPair.controller)
        .sign(app.key.keyLike)

      redirectUrl = `${app.env.waciHost}/authenticate/${authToken}`

      return reply.status(200).send({
        success: true,
        verifiable_presentation: vp,
        authToken,
        redirectUrl,
      })
    },
  )

  // *************************
  // Sign In
  // *************************

  app.get<shared.api.waci.request.challengeToken.RouteInterface>(
    shared.api.waci.request.challengeToken.path,
    {
      schema: shared.api.waci.request.challengeToken.schema,
    },
    async (req, reply) => {
      const challengeToken = await new SignRequestChallengeJWT({
        presentation_definition: {
          id: uuid(),
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
        .setProtectedHeader({alg: 'EdDSA', kid: app.key.keyPair.id})
        .setSubject(req.query.token)
        .setJti(uuid())
        .setExpirationTime('30m')
        .setIssuer(app.key.keyPair.controller)
        .sign(app.key.keyLike)

      return reply.status(200).send({
        success: true,
        challengeToken,
      })
    },
  )

  app.post<shared.api.waci.request.submit.RouteInterface>(
    shared.api.waci.request.submit.path,
    {
      schema: shared.api.waci.request.submit.schema,
    },
    async (req, reply) => {
      const isUsed = await isTokenUsed(req.body.responseToken)

      if (isUsed) {
        return reply.status(400).send({
          success: false,
          message: 'Token has already been used'
        })
      }

      let result

      try {
        result = await requestResponseJwtVerify(
          req.body.responseToken,
          {
            key: getResponseTokenKey,
          },
          {
            key: app.key.keyLike,
            options: {
              issuer: app.key.keyPair.controller
            }
          }
        )

        const {sub} = result.challenge.payload

        if (typeof sub !== 'string') throw new Error('Subject not set')
        if (typeof result.challenge.payload.exp !== 'number') throw new Error('Missing exp')

        await useToken(req.body.responseToken, new Date(result.challenge.payload.exp * 1000))
      } catch (e) {
        console.log(e)
        return reply.status(401).send({
          success: false,
          message: 'Response token is not valid'
        })
      }

      const presentation: Object = result.response.payload['verifiable_presentation'] as Object

      const validationResult = await validateVPV1({
        documentLoader: app.documentLoader,
        getVerifySuite: async ({controller, verificationMethod}) => {
          const {didDocument} = await app.resolveDID(controller)
          if (!didDocument) {
            throw new Error('Cannot resolve DID Doc for controller')
          }

          const idchar: any = controller.split('did:key:').pop();
          const encodedType = idchar.substring(0, 4);
          let jws = undefined;
          if (encodedType == 'z6Mk'){
              try {
                const id = didDocument.verificationMethod?.find(({id}) => verificationMethod.includes(id))
                const key = await JsonWebKey.from({
                  id: verificationMethod,
                  type: "Ed25519VerificationKey2018",
                  controller: controller,
                  publicKeyBase58: id!.publicKeyBase58 as string,
                  privateKeyBase58: id!.publicKeyBase58 as string,
                });
                jws = new JsonWebSignature({
                  key: key,
                });
              } catch (error) {
                console.log(error);
              }
          }
          else{
              const publicKeyJwk = await getPublicJwkForKey(controller, verificationMethod, didDocument)

              jws = new JsonWebSignature({
              key: await JsonWebKey.from({
                id: verificationMethod,
                controller,
                type: 'JsonWebKey2020',
                privateKeyJwk: publicKeyJwk,
                publicKeyJwk: publicKeyJwk,
              }),
            });
        }

          return jws;
        },
      })(presentation as any)

      if (validationResult.kind === 'invalid') {
        return reply.status(400).send({
          success: false,
          message: 'Invalid Presentation Submission'
        })
      }

      let credentialrefId: string

      try {
        const credential: VCAccountPersonV1 = validationResult.data.verifiableCredential[0] as any
        const issuerDid = parse(credential.issuer)?.did
        const ourDid = parse(app.key.keyPair.controller)?.did
        if (!issuerDid || !ourDid || issuerDid !== ourDid) {
          throw new Error('Not issued by Tilly')
        }
        const credentialref = credential.credentialSubject.data.hasAccount.identifier
        const Credentialref = await Credentialrefs.getRepo().findOneOrFail({where: {credentialref}})
        credentialrefId = Credentialref.id
      } catch {
        return reply.status(400).send({
          success: false,
          message: 'Account credential not found in submission'
        })
      }

      const authToken = await new SignJWT({})
        .setProtectedHeader({alg: 'EdDSA', kid: app.key.keyPair.id})
        .setSubject(credentialrefId)
        .setExpirationTime('30m')
        .setIssuer(app.key.keyPair.controller)
        .sign(app.key.keyLike)

      let redirectUrl: string | undefined
      redirectUrl = `${app.env.waciHost}/authenticate/${authToken}`
      
      return reply.status(200).send({
        success: true,
        authToken,
        redirectUrl,
      })
    },
  )

  app.post<shared.api.waci.request.authenticate.RouteInterface>(
    shared.api.waci.request.authenticate.path,
    {
      schema: shared.api.waci.request.authenticate.schema,
    },
    async (req, reply) => {
      const isUsed = await isTokenUsed(req.body.token)

      if (isUsed) {
        return reply.status(400).send({
          success: false,
          message: 'Token has already been used'
        })
      }

      let result
      try {
        result = await jwtVerify(req.body.token, app.key.keyLike, {issuer: app.key.keyPair.controller})
        if (typeof result.payload.exp !== 'number') throw new Error('Expiration not set')
        if (typeof result.payload.sub === 'undefined') throw new Error('Subject not set')

        await useToken(req.body.token, new Date(result.payload.exp * 1000))
      } catch {
        return clearWebSocketCookie(reply).status(400).send({
          success: false,
          message: 'Token is invalid'
        })
      }

      return setCredentialrefCookie(reply, result.payload.sub).status(200).send({
        success: true
      })
    },
  )

  // *************************
  // Available
  // *************************

  app.post<shared.api.waci.available.RouteInterface>(
    shared.api.waci.available.path,
    {
      schema: shared.api.waci.available.schema,
    },
    async (req, reply) => {
      const count = await Credentialrefs.getRepo().count({where: {credentialref: req.body.credentialref}})

      return reply.status(200).send({
        available: count >= 1 ? false : true,
        success: true,
      })
    },
  )

  // *************************
  // Me
  // *************************

  app.get<shared.api.waci.me.RouteInterface>(
    shared.api.waci.me.path,
    {
      schema: shared.api.waci.me.schema,
      preHandler: app.auth([verifyCredentialref]),
    },
    async (req, reply) => {
      const credentialref = getCredentialref(req)

      return reply.status(200).send({
        credentialref: credentialref.toView(),
        success: true,
      })
    },
  )

  // *************************
  // Log Out
  // *************************

  app.get<shared.api.waci.logOut.RouteInterface>(
    shared.api.waci.logOut.path,
    {
      schema: shared.api.waci.logOut.schema,
    },
    async (_, reply) => {
      clearCredentialrefCookie(reply)
      clearWebSocketCookie(reply)

      return reply.status(200).send({
        success: true
      })
    },
  )
}
