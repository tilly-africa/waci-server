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
var Credentialrefs_1;
Object.defineProperty(exports, "__esModule", { value: true });
exports.Credentialrefs = void 0;
const typeorm_1 = require("typeorm");
const database_1 = require("../database");
let Credentialrefs = Credentialrefs_1 = class Credentialrefs {
    constructor() {
        this.toView = () => ({
            id: this.id,
            credentialref: this.credentialref,
            createdAt: this.createdAt.toISOString(),
            updatedAt: this.updatedAt.toISOString(),
        });
    }
};
Credentialrefs.getRepo = () => database_1.databaseManager.getRepository(Credentialrefs_1);
__decorate([
    typeorm_1.PrimaryGeneratedColumn('uuid'),
    __metadata("design:type", String)
], Credentialrefs.prototype, "id", void 0);
__decorate([
    typeorm_1.Column({ type: 'citext', unique: true }),
    __metadata("design:type", String)
], Credentialrefs.prototype, "credentialref", void 0);
__decorate([
    typeorm_1.CreateDateColumn({ name: 'created_at' }),
    __metadata("design:type", Date)
], Credentialrefs.prototype, "createdAt", void 0);
__decorate([
    typeorm_1.UpdateDateColumn({ name: 'updated_at' }),
    __metadata("design:type", Date)
], Credentialrefs.prototype, "updatedAt", void 0);
Credentialrefs = Credentialrefs_1 = __decorate([
    typeorm_1.Entity({ name: 'credentialrefs' })
], Credentialrefs);
exports.Credentialrefs = Credentialrefs;
//# sourceMappingURL=Credentialrefs.js.map