import { CredentialView } from '@tilly-waci/shared'
import { Entity, Column, PrimaryColumn, Repository, CreateDateColumn, UpdateDateColumn } from 'typeorm'
import { databaseManager } from '../database'

@Entity({ name: 'credentials' })
export class Credentials {
  @PrimaryColumn('uuid')
  id!: string

  @Column({type: 'json'})
  credentialobject!: Object

  @Column({type: 'json'})
  holder!: Object;

  @Column({name: 'issuance_date',  nullable: true})
  issuanceDate!: string

  @Column({ nullable: true,})
  issuer!: string

  @CreateDateColumn({name: 'created_at'})
  createdAt!: Date

  @UpdateDateColumn({name: 'updated_at'})
  updatedAt!: Date

  toView = (): CredentialView => ({
    id: this.id,
    credentialobject: this.credentialobject,
    holder: this.holder,
    issuanceDate: this.issuanceDate,
    issuer: this.issuer,
    createdAt: this.createdAt.toISOString(),
    updatedAt: this.updatedAt.toISOString(),
  })

  static getRepo = (): Repository<Credentials> => databaseManager.getRepository(Credentials)
}
