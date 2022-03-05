import S from 'fluent-json-schema'

export type CredentialView = {
  id: string;
  credentialobject: Object;
  holder: Object;
  issuanceDate: String;
  issuer: string;
  updatedAt: string;
  createdAt: string;
};

export const credentialView = S.object()
         .prop('id', S.string().format('uuid'))
         .prop('updatedAt', S.string().format('date-time'))
         .prop('createdAt', S.string().format('date-time'))
         .required([
           'id',
           'issuer',
           'credentialobject',
           'issuanceDate',
           'updatedAt',
           'createdAt',
         ]);


