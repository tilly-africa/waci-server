import S from 'fluent-json-schema'
// import { VP } from '@bloomprotocol/vc';


import { jwtRegex } from '../../../util'
import { BaseSuccessReply, BaseFailReply, base4XXResponse, base200Response } from '../../base'

export type Body = {
  responseToken: string
  from: 'button' | 'qr'
}
export type Querystring = unknown
export type Params = unknown
export type Headers = unknown

export type SuccessReply = BaseSuccessReply & {
  verifiable_presentation: any
  redirectUrl?: string
  authToken?: string
}

export type FailReply = BaseFailReply

export type Reply = SuccessReply | FailReply

export type RouteInterface = {
  Body: Body
  Querystring: Querystring
  Params: Params
  Headers: Headers
  Reply: Reply
}

export const schema = {
  body: S.object()
    .prop('responseToken', S.string().pattern(jwtRegex))
    .prop('from', S.string().enum(['button', 'qr']))
    .required(['responseToken', 'from']),
  querystring: undefined,
  params: undefined,
  headers: undefined,
  response: {
    200: S.object()
      .prop('verifiable_presentation', S.object().additionalProperties(true))
      .prop('redirectUrl', S.string().format('url'))
      .prop('authToken', S.string())
      .required(['verifiable_presentation'])
      .extend(base200Response),
    '4xx': base4XXResponse,
  },
}

export const path = '/api/v1/waci/offer/submit'
