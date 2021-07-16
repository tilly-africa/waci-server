"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var Credentials_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.Credentials = void 0;
const typeorm_1 = require("typeorm");
const database_1 = require("../database");
let Credentials = Credentials_1 = class Credentials {
    constructor() {
        this.toView = () => ({
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
        });
    }
};
Credentials.getRepo = () => database_1.databaseManager.getRepository(Credentials_1);
__decorate([
    typeorm_1.PrimaryColumn('uuid'),
    __metadata("design:type", String)
], Credentials.prototype, "id", void 0);
__decorate([
    typeorm_1.Column({ type: 'json' }),
    __metadata("design:type", Object)
], Credentials.prototype, "type", void 0);
__decorate([
    typeorm_1.Column({ type: 'json' }),
    __metadata("design:type", Object)
], Credentials.prototype, "holder", void 0);
__decorate([
    typeorm_1.Column({ name: 'credential_subject', type: 'json' }),
    __metadata("design:type", Object)
], Credentials.prototype, "credentialSubject", void 0);
__decorate([
    typeorm_1.Column({ type: 'json' }),
    __metadata("design:type", Object)
], Credentials.prototype, "context", void 0);
__decorate([
    typeorm_1.Column({ name: 'issuance_date', nullable: true }),
    __metadata("design:type", Date)
], Credentials.prototype, "issuanceDate", void 0);
__decorate([
    typeorm_1.Column({ nullable: true, }),
    __metadata("design:type", String)
], Credentials.prototype, "issuer", void 0);
__decorate([
    typeorm_1.Column({ type: 'json', nullable: true }),
    __metadata("design:type", Object)
], Credentials.prototype, "proof", void 0);
__decorate([
    typeorm_1.CreateDateColumn({ name: 'created_at' }),
    __metadata("design:type", Date)
], Credentials.prototype, "createdAt", void 0);
__decorate([
    typeorm_1.UpdateDateColumn({ name: 'updated_at' }),
    __metadata("design:type", Date)
], Credentials.prototype, "updatedAt", void 0);
Credentials = Credentials_1 = __decorate([
    typeorm_1.Entity({ name: 'credentials' })
], Credentials);
exports.Credentials = Credentials;
//# sourceMappingURL=Credentials.js.map