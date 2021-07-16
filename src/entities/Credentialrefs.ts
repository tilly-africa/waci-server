import { CredentialrefView } from '@tilly-waci/shared'
import { Entity, Column, PrimaryGeneratedColumn, Repository, CreateDateColumn, UpdateDateColumn } from 'typeorm'

import { databaseManager } from '../database'

@Entity({ name: 'credentialrefs' })
export class Credentialrefs {
  @PrimaryGeneratedColumn('uuid')
  id!: string

  @Column({ type: 'citext', unique: true })
  credentialref!: string

  @CreateDateColumn({name: 'created_at'})
  createdAt!: Date

  @UpdateDateColumn({name: 'updated_at'})
  updatedAt!: Date

  toView = (): CredentialrefView => ({
    id: this.id,
    credentialref: this.credentialref,
    createdAt: this.createdAt.toISOString(),
    updatedAt: this.updatedAt.toISOString(),
  })

  static getRepo = (): Repository<Credentialrefs> => databaseManager.getRepository(Credentialrefs)
}
