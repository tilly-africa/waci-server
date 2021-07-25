import { CredentialView } from '@tilly-waci/shared'
import { Entity, Column, PrimaryColumn, Repository, CreateDateColumn, UpdateDateColumn } from 'typeorm'
import { VCProof, VCSubject } from '@bloomprotocol/vc';

import { databaseManager } from '../database'

@Entity({ name: 'credentials' })
export class Credentials {
  @PrimaryColumn('uuid')
  id!: string

  @Column({type: 'json'})
  type!: string | string []

  @Column({type: 'json'})
  holder!: Object;

  @Column({ name: 'credential_subject', type: 'json'})
  credentialSubject!: VCSubject

  @Column({type: 'json'})
  context!: Array<Object>

  @Column({name: 'issuance_date',  nullable: true})
  issuanceDate!: Date

  @Column({ nullable: true,})
  issuer!: string

  @Column({type: 'json',  nullable: true})
  proof!: VCProof

  @CreateDateColumn({name: 'created_at'})
  createdAt!: Date

  @UpdateDateColumn({name: 'updated_at'})
  updatedAt!: Date

  toView = (): CredentialView => ({
    id: this.id,
    type: this.type,
    holder: this.holder,
    credentialSubject: this.credentialSubject,
    context: this.context,
    issuanceDate: this.issuanceDate,
    issuer: this.issuer,
    proof: this.proof,
    createdAt: this.createdAt.toISOString(),
    updatedAt: this.updatedAt.toISOString(),
  })

  static getRepo = (): Repository<Credentials> => databaseManager.getRepository(Credentials)
}
