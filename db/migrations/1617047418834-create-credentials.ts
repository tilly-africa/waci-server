import {MigrationInterface, QueryRunner, Table} from "typeorm";

export class createCredentials1617047418834 implements MigrationInterface {

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'credentials',
        columns: [
          {
            name: 'id',
            type: 'uuid',
            isUnique: true,
          },
          {
            name: 'type',
            type: 'json',
          },
          {
            name: 'holder',
            type: 'json',
          },
          {
            name: 'context',
            type: 'json',
          },
          {
            name: 'credential_subject',
            type: 'json',
          },
          {
            name: 'issuance_date',
            type: 'varchar',
            isNullable: true
          },
          {
            name: 'issuer',
            type: 'varchar',
            isNullable: true
          },
          {
            name: 'proof',
            type: 'json',
            isNullable: true
          },
          {
            name: 'created_at',
            type: 'timestamp',
            default: 'now()',
          },
          {
            name: 'updated_at',
            type: 'timestamp',
            default: 'now()',
          },
        ],
      }),
    )
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.dropTable('credentials')
  }
}
