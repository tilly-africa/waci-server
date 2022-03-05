import fp from 'fastify-plugin'
import { FastifyPluginCallback } from 'fastify'

import { KeyLike } from 'jose/types'
import { parseJwk } from 'jose/jwk/parse'

import { EcdsaSecp256k1VerificationKey2019, keyUtils } from '@bloomprotocol/ecdsa-secp256k1-verification-key-2019'
import {resolverRegistry} from '@bloomprotocol/elem-did-legacy-non-anchored'
import { DIDResolutionResult, Resolver } from 'did-resolver'

const base58 = require('base58-universal')
const jsonld = require('jsonld')


type DIDPluginOptions = {
  controller: string
  id: string
  publicKeyHex: string;
  privateKeyHex: string;
}

const pluginCallback: FastifyPluginCallback<DIDPluginOptions> = async (fastify, {controller, id, publicKeyHex, privateKeyHex}, done) => {

  const keyPair = new EcdsaSecp256k1VerificationKey2019({
    publicKeyBase58: base58.encode(Buffer.from(publicKeyHex, 'hex')), 
    privateKeyBase58: base58.encode(Buffer.from(privateKeyHex, 'hex')), 
    id: id, 
    controller: controller, 
    revoked: false
  })
  

  const resolveDID = (did: string): Promise<DIDResolutionResult> => {
    return new Resolver(resolverRegistry).resolve(did)
  }

  const documentLoader = async (url: string) => {
    if (url.startsWith('did:')) {
      const {didDocument} = await resolveDID(url)

      return {
        contextUrl: null,
        document: didDocument,
        documentUrl: url,
      }
    }
    console.log(url)

    return jsonld.documentLoaders.node()(url)
  }

  fastify.decorate('documentLoader', documentLoader)
  fastify.decorate('resolveDID', resolveDID)
  fastify.decorate('key', {
    keyPair,
    keyLike: await parseJwk(keyUtils.privateKeyJWKFrom.privateKeyBase58(keyPair.privateKeyBase58!, id), 'ES256K')
  })

  done()
}

export const didPlugin = fp<DIDPluginOptions>(pluginCallback, '3.x')

declare module 'fastify' {
  interface FastifyInstance {
    key: {
      keyPair: EcdsaSecp256k1VerificationKey2019,
      keyLike: KeyLike
    },
    resolveDID: (did: string) => Promise<DIDResolutionResult>
    documentLoader: (url: string) => Promise<any>
  }
}
