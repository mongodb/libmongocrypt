import bindings = require('bindings');

const mc = bindings('mongocrypt');

export interface MongoCryptKMSRequest {
  addResponse(response: Uint8Array): void;
  readonly status: MongoCryptStatus;
  readonly bytesNeeded: number;
  readonly kmsProvider: string;
  readonly endpoint: string;
  readonly message: Buffer;
}

export interface MongoCryptStatus {
  type: number;
  code: number;
  message?: string;
}

export interface MongoCryptContext {
  nextMongoOperation(): Buffer;
  addMongoOperationResponse(response: Uint8Array): void;
  finishMongoOperation(): void;
  nextKMSRequest(): MongoCryptKMSRequest | null;
  provideKMSProviders(providers: Uint8Array): void;
  finishKMSRequests(): void;
  finalize(): Buffer;

  readonly status: MongoCryptStatus;
  readonly state: number;
}

export interface MongoCryptConstructor {
  new (options: {
    kmsProviders?: Uint8Array;
    schemaMap?: Uint8Array;
    encryptedFieldsMap?: Uint8Array;
    logger?: unknown;
    cryptoCallbacks?: Record<string, unknown>;
    cryptSharedLibSearchPaths?: string[];
    cryptSharedLibPath?: string;
    bypassQueryAnalysis?: boolean;
  }): MongoCrypt;
  libmongocryptVersion: string;
}

export interface MongoCrypt {
  makeEncryptionContext(ns: string, command: Uint8Array): MongoCryptContext;
  makeExplicitEncryptionContext(
    value: Uint8Array,
    options?: {
      keyId?: Uint8Array;
      keyAltName?: Uint8Array;
      algorithm?: string;
      rangeOptions?: Uint8Array;
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
  makeDecryptionContext(buffer: Uint8Array): MongoCryptContext;
  makeExplicitDecryptionContext(buffer: Uint8Array): MongoCryptContext;
  makeDataKeyContext(
    optionsBuffer: Uint8Array,
    options: {
      keyAltNames?: Uint8Array[];
      keyMaterial?: Uint8Array;
    }
  ): MongoCryptContext;
  makeRewrapManyDataKeyContext(filter: Uint8Array, encryptionKey?: Uint8Array): MongoCryptContext;
  readonly status: MongoCryptStatus;
  readonly cryptSharedLibVersionInfo: {
    version: bigint;
    versionStr: string;
  } | null;
}

export type ExplicitEncryptionContextOptions = NonNullable<
  Parameters<MongoCrypt['makeExplicitEncryptionContext']>[1]
>;
export type DataKeyContextOptions = NonNullable<Parameters<MongoCrypt['makeDataKeyContext']>[1]>;
export type MongoCryptOptions = NonNullable<ConstructorParameters<MongoCryptConstructor>[0]>;

export const MongoCrypt: MongoCryptConstructor = mc.MongoCrypt;

/** exported for testing only. */
interface MongoCryptContextCtor {
  new (): MongoCryptContext;
}
export const MongoCryptContextCtor: MongoCryptContextCtor = mc.MongoCryptContextCtor;
