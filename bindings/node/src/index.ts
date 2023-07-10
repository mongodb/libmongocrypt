import * as bindings from 'bindings';

const mc = bindings('mongocrypt');

export interface MongoCryptCtor {
  new (): MongoCryptInstance;
  libmongocryptVersion: string;
}

interface MongoCryptKMSRequest {
  addResponse(response: Buffer): void;
  status: MongoCryptStatus;
  bytesNeeded: number;
  kmsProvider: string;
  endpoint: string;
  message: Buffer;
}

interface MongoCryptStatus {
  type: number;
  code: number;
  message?: string;
}

interface MongoCryptContext {
  nextMongoOperation(): Buffer;
  addMongoOperationResponse(response: Buffer): void;
  finishMongoOperation(): void;
  nextKMSRequest(): MongoCryptKMSRequest | null;
  provideKMSProviders(providers: Buffer): void;
  finishKMSRequests(): void;
  finalize(): Buffer;

  status: MongoCryptStatus;
  state: number;
}

export interface MongoCryptInstance {
  makeEncryptionContext(ns: string, command: Buffer): MongoCryptContext;
  makeExplicitEncryptionContext(
    value: Buffer,
    options?: {
      keyId?: Buffer;
      keyAltName?: Buffer;
      algorithm?: string;
      rangeOptions?: Buffer;
      contentionFactor?: bigint | number;
      queryType?: string;

      /**
       * node-binding specific option
       *
       * When true, creates a `mongocrypt_ctx_explicit_encrypt_expression` context.
       * When false, creates a `mongocrypt_ctx_explicit_encrypt`
       */
      expressionMode: boolean;
    }
  ): MongoCryptContext;
  makeDecryptionContext(buffer: Buffer): MongoCryptContext;
  makeExplicitDecryptionContext(buffer: Buffer): MongoCryptContext;
  makeDataKeyContext(
    optionsBuffer: Buffer,
    options: {
      keyAltNames: Buffer[];
      keyMaterial: Buffer;
    }
  ): void;
  makeRewrapManyDataKeyContext(filter: Buffer, encryptionKey: Buffer): void;
  status: MongoCryptStatus;
  cryptSharedLibVersionInfo: {
    version: bigint;
    versionStr: string;
  } | null;
}

export const MongoCrypt: MongoCryptCtor = mc.MongoCrypt;
