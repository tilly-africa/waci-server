import S from 'fluent-json-schema'

export type CredentialView = {
  id: string;
  type: string | string[];
  credentialSubject: Object;
  holder: Object;
  context: Array<Object>;
  issuanceDate: Date;
  issuer: string;
  proof: Object;
  updatedAt: string
  createdAt: string
}

export const credentialView = S.object()
  .prop('id', S.string().format('uuid'))
  .prop('updatedAt', S.string().format('date-time'))
  .prop('createdAt', S.string().format('date-time'))
  .required(['id', 'type', 'issuer', 'proof', 'credentialSubject', 'context', 'issuanceDate', 'updatedAt', 'createdAt'])
