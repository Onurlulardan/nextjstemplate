// Veritabanı enum tipleri

// $Enums namespace'i Prisma'nın ürettiği enum tiplerini taklit ediyor
export namespace $Enums {
  export enum RoleType {
    ADMIN = 'ADMIN',
    MEMBER = 'MEMBER'
  }

  export enum UserStatus {
    ACTIVE = 'ACTIVE',
    INACTIVE = 'INACTIVE',
    SUSPENDED = 'SUSPENDED'
  }

  export enum OrgStatus {
    ACTIVE = 'ACTIVE',
    INACTIVE = 'INACTIVE',
    SUSPENDED = 'SUSPENDED'
  }

  export enum PermissionTarget {
    USER = 'USER',
    ROLE = 'ROLE',
    ORGANIZATION = 'ORGANIZATION'
  }
}

// Aynı enum'ları doğrudan export da ediyoruz
export const RoleType = $Enums.RoleType;
export const UserStatus = $Enums.UserStatus;
export const OrgStatus = $Enums.OrgStatus;
export const PermissionTarget = $Enums.PermissionTarget;

export type RoleType = $Enums.RoleType;
export type UserStatus = $Enums.UserStatus;
export type OrgStatus = $Enums.OrgStatus;
export type PermissionTarget = $Enums.PermissionTarget;
