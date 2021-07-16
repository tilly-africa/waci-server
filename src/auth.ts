import { FastifyRequest } from 'fastify'
import { FastifyAuthFunction } from 'fastify-auth'

import { Credentialrefs } from '@server/entities/Credentialrefs'
import { credentialrefCookieKey, webSocketCookieKey } from '@server/cookies'

export const verifyCredentialref : FastifyAuthFunction = async (req, reply) => {
  const signedCookie = req.cookies[credentialrefCookieKey]
  if (!signedCookie) throw new Error('Not authorized to interact with credential')

  const { valid, value: credentialrefId } = reply.unsignCookie(signedCookie)

  if (!valid) throw new Error('Cookie is invalid')
  if (!credentialrefId) throw new Error('Not authorized to interact with credential')

  const credentialref = await Credentialrefs.getRepo().findOne({ where: { id: credentialrefId } })
  if (!credentialref) throw new Error('credential ref does not exist')

  req.credentialref = credentialref
}

export const getCredentialref = (req: FastifyRequest): Credentialrefs => {
  const { credentialref } = req
  if (typeof credentialref === 'undefined') throw new Error('Credential ref  not attached to request')

  return credentialref
}

export const verifyWebsocketToken: FastifyAuthFunction = async (req, reply) => {
  const signedCookie = req.cookies[webSocketCookieKey]
  if (!signedCookie) throw new Error('No websocket token')

  const { valid, value: wsToken } = reply.unsignCookie(signedCookie)

  if (!valid) throw new Error('Cookie is invalid')
  if (!wsToken) throw new Error('No websocket token')

  req.wsToken = wsToken
}

export const getWebsocketToken = (req: FastifyRequest): string => {
  const { wsToken } = req
  if (typeof wsToken === 'undefined') throw new Error('Web socket token not attached to request')

  return wsToken
}
