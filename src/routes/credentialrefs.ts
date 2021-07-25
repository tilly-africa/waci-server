import { FastifyInstance } from 'fastify'
import * as shared from '@tilly-waci/shared'
import base64url from 'base64url';
import { jwtVerify, JWTVerifyGetKey } from 'jose/jwt/verify';
import { SignJWT } from 'jose/jwt/sign';
import { parseJwk } from 'jose/jwk/parse';
import { JWTPayload } from 'jose/types';
import { v4 as uuid } from 'uuid'

import {  parse } from 'did-resolver'

import { verifyCredentialref, getCredentialref } from '@server/auth'
import { clearCredentialrefCookie, clearWebSocketCookie, setCredentialrefCookie } from '@server/cookies'
import { Credentialrefs } from '@server/entities/Credentialrefs'
import { Credentials } from '@server/entities/Credentials'

import { isTokenUsed, useToken } from '@server/entities/UsedTokens';
import { SignOfferChallengeJWT, offerResponseJwtVerify, SignRequestChallengeJWT, requestResponseJwtVerify } from '@server/waciJose'

import { VC, signVC, VP, signVP, verifyVP, verifyVC } from '@bloomprotocol/vc';
import { keyUtils, EcdsaSecp256k1VerificationKey2019 } from '@bloomprotocol/ecdsa-secp256k1-verification-key-2019'
import { EcdsaSecp256k1Signature2019  } from '@bloomprotocol/ecdsa-secp256k1-signature-2019'

const base58 = require('base58-universal')

// import { got} from 'got'
// const jsonld = require('jsonld');

export const applyCredentialrefRoutes = (app: FastifyInstance): void => {
  // *************************
  // Utils
  // *************************

  const getPublicJwkForKey = async (did: string, keyId: string, didDoc: any) => {
    const l  = keyUtils.publicKeyJWKFrom.publicKeyHex(didDoc.publicKey[0]['publicKeyHex'], keyId)
    return l
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

    if (didDocument.id.startsWith('did:elem')) { 
      const parsedjwk = await parseJwk(await getPublicJwkForKey(payload.iss, header.kid, didDocument), header.alg)
      return parsedjwk
    } else {
      throw new Error('Unsupported DID Method')
    }
  }

  const getSuite = async ({ verificationMethod, controller, proofType }: any) => {
    switch (proofType) {
      case 'EcdsaSecp256k1Signature2019':
        if (controller.startsWith('did:elem') && controller.indexOf('elem:initial-state') >= 0) {
          const {didDocument}: any = await app.resolveDID(controller)
          if (!didDocument) throw new Error(`Could not resolve DID: ${controller}`)

          const sig  = new EcdsaSecp256k1Signature2019({ 
                  key: EcdsaSecp256k1VerificationKey2019.from({
                    controller, 
                    id: verificationMethod,
                    publicKeyBase58: base58.encode(Buffer.from(didDocument.publicKey[0]['publicKeyHex'], 'hex')),
                    privateKeyBase58: base58.encode(Buffer.from(didDocument.publicKey[0]['publicKeyHex'], 'hex')),
                  })
                });

          return sig
        }
  
        return new EcdsaSecp256k1Signature2019()
      default:
        throw new Error(`Unsupported proofType: ${proofType}`)
    }
  }
  
  const getProofPurposeOptions = async ({controller, proofPurpose} : any) => {
    switch (proofPurpose) {
      case 'assertionMethod':
      case 'authentication':
        const { didDocument } = await app.resolveDID(controller)
        if (controller.startsWith('did:elem') && controller.indexOf('elem:initial-state') >= 0) {
          return {
            controller: didDocument,
          }
        }
  
        return {}
      default:
        throw new Error(`Unsupported proofPurpose: ${proofPurpose}`)
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
                  path: ['$.credentialSubject.@id'],
                },
              },
            },
          ],
        },
        callbackUrl: app.env.waciHost + `${shared.api.waci.offer.submit.path}`,
        credentialref: req.query.credentialref,
        version: '0.1' as any
      })
        .setProtectedHeader({alg: 'ES256K', kid: app.key.keyPair.id})
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

      const {credentialref } = result.challenge.payload

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

      const unsignedVC: Omit<VC, 'proof'> = {
        '@context': Credential.context,
        id: Credential.id,
        type: Credential.type,
        issuanceDate: new Date().toISOString(),
        issuer: app.key.keyPair.controller,
        credentialSubject: Credential.credentialSubject,
        holder: {id: result.response.payload.iss!}
      }

      const suite = new EcdsaSecp256k1Signature2019({
        key: app.key.keyPair
      });
      
      const credential = await signVC({
        unsigned: unsignedVC,
        suite: suite,
        documentLoader: app.documentLoader,
        addSuiteContext: false
      })

      let validationResult = await verifyVC({vc: credential, 
                documentLoader: app.documentLoader,
                getSuite: getSuite, 
                getProofPurposeOptions: getProofPurposeOptions
              })
      console.log(validationResult.success)
      
      const unsignedVP: Omit<VP, 'proof'> = {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        id: `urn:uuid:${uuid()}`,
        type: ['VerifiablePresentation'],
        holder: {
          id:  app.key.keyPair.controller
        },
        verifiableCredential: [credential]
      }
      
      const vp = await signVP({
        unsigned: unsignedVP,
        suite:  new EcdsaSecp256k1Signature2019({
          key: app.key.keyPair
        }),
        proofPurposeOptions: {
          challenge: uuid(),
          domain: 'https://credentials.tilly.africa'
        },
        documentLoader: app.documentLoader,
      })

      let validationResult2 = await verifyVP({
        vp: vp, 
        getSuite: getSuite, 
        documentLoader: app.documentLoader,
        getProofPurposeOptions: getProofPurposeOptions,
      })

      console.log(validationResult2.success)
      
      let redirectUrl: string | undefined

      const authToken = await new SignJWT({})
        .setProtectedHeader({alg: 'ES256K', kid: app.key.keyPair.id})
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
        .setProtectedHeader({alg: 'ES256K', kid: app.key.keyPair.id})
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

      const vc = presentation['verifiableCredential'][0]
      const validationResult1 = await verifyVC({vc: vc, 
        documentLoader: app.documentLoader,
        getSuite: getSuite, 
        getProofPurposeOptions: getProofPurposeOptions
      })

      console.log(validationResult1.success)

      const validationResult = await verifyVP({
        vp: presentation, 
        getSuite: getSuite, 
        documentLoader: app.documentLoader,
        getProofPurposeOptions: getProofPurposeOptions,
      })

      if (validationResult.success === false) {
        console.log(validationResult)
        return reply.status(400).send({
          success: false,
          message: 'Invalid Presentation Submission'
        })
      }

      let credentialrefId: string

      try {

        const credential = validationResult.vp.verifiableCredential[0] as any

        const issuerDid = parse(credential.issuer)?.did
        const ourDid = parse(app.key.keyPair.controller)?.did
        if (!issuerDid || !ourDid || issuerDid !== ourDid) {
          throw new Error('Not issued by Tilly')
        }
        const credentialref = credential.credentialSubject['@id']
        const Credentialref = await Credentialrefs.getRepo().findOneOrFail({where: {credentialref}})
        credentialrefId = Credentialref.id
      } catch {
        return reply.status(400).send({
          success: false,
          message: 'Account credential not found in submission'
        })
      }

      const authToken = await new SignJWT({})
        .setProtectedHeader({alg: 'ES256K', kid: app.key.keyPair.id})
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
