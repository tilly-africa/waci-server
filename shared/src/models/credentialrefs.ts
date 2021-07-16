import S from 'fluent-json-schema'

export type CredentialrefView = {
  id: string
  credentialref: string
  updatedAt: string
  createdAt: string
}

export const credentialrefView = S.object()
  .prop('id', S.string().format('uuid'))
  .prop('credentialref', S.string())
  .prop('updatedAt', S.string().format('date-time'))
  .prop('createdAt', S.string().format('date-time'))
  .required(['id', 'credentialref', 'updatedAt', 'createdAt'])
