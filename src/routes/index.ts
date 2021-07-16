import { FastifyInstance, FastifyPluginCallback } from 'fastify'

import { applyDIDRoutes } from './did'
import { applyCredentialrefRoutes } from './credentialrefs'
import { applyWebsocketRoutes } from './websocket'

export const routes: FastifyPluginCallback = (app: FastifyInstance, _, done): void => {
  applyDIDRoutes(app)
  applyCredentialrefRoutes(app)
  applyWebsocketRoutes(app)

  done()
}
