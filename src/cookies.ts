import { FastifyReply } from 'fastify'

export const credentialrefCookieKey = 'tw_credentialref'
const credentialrefCookieKeyMaxAge = 365 * 24 * 60 * 60 * 1000

export const webSocketCookieKey = 'tw_ws'
const webSocketCookieKeyMaxAge = 365 * 24 * 60 * 60 * 1000

const setCookie = (cookieKey: string, maxAge: number) => <T extends FastifyReply>(reply: T, value: string) =>
  reply.setCookie(cookieKey, value, {
    maxAge,
    signed: true,
    httpOnly: true,
    path: '/',
    sameSite: 'strict',
    secure: true,
  })

export const setCredentialrefCookie = setCookie(credentialrefCookieKey, credentialrefCookieKeyMaxAge)

export const setWebSocketCookie = setCookie(webSocketCookieKey, webSocketCookieKeyMaxAge)

const clearCookie = (cookieKey: string) => <T extends FastifyReply>(reply: T) => reply.clearCookie(cookieKey)

export const clearCredentialrefCookie = clearCookie(credentialrefCookieKey)

export const clearWebSocketCookie = clearCookie(credentialrefCookieKey)
