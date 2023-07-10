import type {
  MongoClient,
  BulkWriteResult,
  DeleteResult,
  FindCursor,
  Collection,
  Db,
  CreateCollectionOptions,
  Document,
  Binary,
  Long
} from 'mongodb';

export type ClientEncryptionDataKeyProvider = 'aws' | 'azure' | 'gcp' | 'local' | 'kmip';

/**
 * The schema for a DataKey in the key vault collection.
 */
export interface DataKey {
  _id: Binary;
  version?: number;
  keyAltNames?: string[];
  keyMaterial: Binary;
  creationDate: Date;
  updateDate: Date;
  status: number;
  masterKey: Document;
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 *
 * An error indicating that something went wrong specifically with MongoDB Client Encryption
 */
export class MongoCryptError extends Error {
  cause?: Error;
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 *
 * An error indicating that `ClientEncryption.createEncryptedCollection()` failed to create a collection
 */
export class MongoCryptCreateEncryptedCollectionError extends MongoCryptError {
  /**
   * The entire `encryptedFields` that was completed while attempting createEncryptedCollection
   */
  encryptedFields: Document;
  /** The error rejected from db.createCollection() */
  cause: Error;
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 *
 * An error indicating that `ClientEncryption.createEncryptedCollection()` failed to create data keys
 */
export class MongoCryptCreateDataKeyError extends MongoCryptError {
  /**
   * The partial `encryptedFields` that was completed while attempting createEncryptedCollection
   */
  encryptedFields: Document;
  /** The first error encountered when attempting to `createDataKey` */
  cause: Error;
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 *
 * An error indicating that mongodb-client-encryption failed to auto-refresh Azure KMS credentials.
 */
export class MongoCryptAzureKMSRequestError extends MongoCryptError {
  /* The body of the IMDS request that produced the error, if present. */
  body?: Document ;
}

/**
 * @deprecated This class will be moved into the [Node driver](https://github.com/mongodb/node-mongodb-native)
 * in the next major version and must be imported from the driver.
 *
 */
export class MongoCryptKMSRequestNetworkTimeoutError extends MongoCryptError {}

/**
 * A set of options for specifying a Socks5 proxy.
 */
export interface ProxyOptions {
  proxyHost: string;
  proxyPort?: number;
  proxyUsername?: string;
  proxyPassword?: string;
}

/**
 * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
 * use the Promise overloads instead.
 */
export interface ClientEncryptionCreateDataKeyCallback {
  /**
   * @param error If present, indicates an error that occurred in the creation of the data key
   * @param dataKeyId If present, returns the id of the created data key
   */
  (error?: Error, dataKeyId?: Binary): void;
}

/**
 * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
 * use the Promise overloads instead.
 */
export interface ClientEncryptionEncryptCallback {
  /**
   * @param error If present, indicates an error that occurred in the process of encryption
   * @param result If present, is the encrypted result
   */
  (error?: Error, result?: Binary): void;
}

/**
 * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
 * use the Promise overloads instead.
 */
export interface ClientEncryptionDecryptCallback {
  /**
   * @param error If present, indicates an error that occurred in the process of decryption
   * @param result If present, is the decrypted result
   */
  (error?: Error, result?: any): void;
}

/**
 * Configuration options that are used by specific KMS providers during key generation, encryption, and decryption.
 */
export interface KMSProviders {
  /**
   * Configuration options for using 'aws' as your KMS provider
   */
  aws?:
    | {
        /**
         * The access key used for the AWS KMS provider
         */
        accessKeyId: string;

        /**
         * The secret access key used for the AWS KMS provider
         */
        secretAccessKey: string;

        /**
         * An optional AWS session token that will be used as the
         * X-Amz-Security-Token header for AWS requests.
         */
        sessionToken?: string;
      }
    | Record<string, never>;

  /**
   * Configuration options for using 'local' as your KMS provider
   */
  local?: {
    /**
     * The master key used to encrypt/decrypt data keys.
     * A 96-byte long Buffer or base64 encoded string.
     */
    key: Buffer | string;
  };

  /**
   * Configuration options for using 'kmip' as your KMS provider
   */
  kmip?: {
    /**
     * The output endpoint string.
     * The endpoint consists of a hostname and port separated by a colon.
     * E.g. "example.com:123". A port is always present.
     */
    endpoint?: string;
  };

  /**
   * Configuration options for using 'azure' as your KMS provider
   */
  azure?:
    | {
        /**
         * The tenant ID identifies the organization for the account
         */
        tenantId: string;

        /**
         * The client ID to authenticate a registered application
         */
        clientId: string;

        /**
         * The client secret to authenticate a registered application
         */
        clientSecret: string;

        /**
         * If present, a host with optional port. E.g. "example.com" or "example.com:443".
         * This is optional, and only needed if customer is using a non-commercial Azure instance
         * (e.g. a government or China account, which use different URLs).
         * Defaults to "login.microsoftonline.com"
         */
        identityPlatformEndpoint?: string | undefined;
      }
    | {
        /**
         * If present, an access token to authenticate with Azure.
         */
        accessToken: string;
      }
    | Record<string, never>;

  /**
   * Configuration options for using 'gcp' as your KMS provider
   */
  gcp?:
    | {
        /**
         * The service account email to authenticate
         */
        email: string;

        /**
         * A PKCS#8 encrypted key. This can either be a base64 string or a binary representation
         */
        privateKey: string | Buffer;

        /**
         * If present, a host with optional port. E.g. "example.com" or "example.com:443".
         * Defaults to "oauth2.googleapis.com"
         */
        endpoint?: string | undefined;
      }
    | {
        /**
         * If present, an access token to authenticate with GCP.
         */
        accessToken: string;
      }
    | Record<string, never>;
}

/**
 * TLS options to use when connecting. The spec specifically calls out which insecure
 * tls options are not allowed:
 *
 *  - tlsAllowInvalidCertificates
 *  - tlsAllowInvalidHostnames
 *  - tlsInsecure
 *  - tlsDisableOCSPEndpointCheck
 *  - tlsDisableCertificateRevocationCheck
 */
export interface ClientEncryptionTlsOptions {
  /**
   * Specifies the location of a local .pem file that contains
   * either the client's TLS/SSL certificate and key or only the
   * client's TLS/SSL key when tlsCertificateFile is used to
   * provide the certificate.
   */
  tlsCertificateKeyFile?: string;
  /**
   * Specifies the password to de-crypt the tlsCertificateKeyFile.
   */
  tlsCertificateKeyFilePassword?: string;
  /**
   * Specifies the location of a local .pem file that contains the
   * root certificate chain from the Certificate Authority.
   * This file is used to validate the certificate presented by the
   * KMS provider.
   */
  tlsCAFile?: string;
}

/**
 * Additional settings to provide when creating a new `ClientEncryption` instance.
 */
export interface ClientEncryptionOptions {
  /**
   * The namespace of the key vault, used to store encryption keys
   */
  keyVaultNamespace: string;

  /**
   * A MongoClient used to fetch keys from a key vault. Defaults to client.
   */
  keyVaultClient?: MongoClient | undefined;

  /**
   * Options for specific KMS providers to use
   */
  kmsProviders?: KMSProviders;

  /**
   * Optional callback to override KMS providers per-context.
   *
   * @deprecated Installing optional dependencies will automatically refresh kms
   *             provider credentials.
   */
  onKmsProviderRefresh?: () => Promise<KMSProviders>;

  /**
   * Options for specifying a Socks5 proxy to use for connecting to the KMS.
   */
  proxyOptions?: ProxyOptions;

  /**
   * TLS options for kms providers to use.
   */
  tlsOptions?: { [kms in keyof KMSProviders]?: ClientEncryptionTlsOptions };
}

/**
 * Configuration options for making an AWS encryption key
 */
export interface AWSEncryptionKeyOptions {
  /**
   * The AWS region of the KMS
   */
  region: string;

  /**
   * The Amazon Resource Name (ARN) to the AWS customer master key (CMK)
   */
  key: string;

  /**
   * An alternate host to send KMS requests to. May include port number.
   */
  endpoint?: string | undefined;
}

/**
 * Configuration options for making an AWS encryption key
 */
export interface GCPEncryptionKeyOptions {
  /**
   * GCP project ID
   */
  projectId: string;

  /**
   * Location name (e.g. "global")
   */
  location: string;

  /**
   * Key ring name
   */
  keyRing: string;

  /**
   * Key name
   */
  keyName: string;

  /**
   * Key version
   */
  keyVersion?: string | undefined;

  /**
   * KMS URL, defaults to `https://www.googleapis.com/auth/cloudkms`
   */
  endpoint?: string | undefined;
}

/**
 * Configuration options for making an Azure encryption key
 */
export interface AzureEncryptionKeyOptions {
  /**
   * Key name
   */
  keyName: string;

  /**
   * Key vault URL, typically `<name>.vault.azure.net`
   */
  keyVaultEndpoint: string;

  /**
   * Key version
   */
  keyVersion?: string | undefined;
}

/**
 * Options to provide when creating a new data key.
 */
export interface ClientEncryptionCreateDataKeyProviderOptions {
  /**
   * Identifies a new KMS-specific key used to encrypt the new data key
   */
  masterKey?:
    | AWSEncryptionKeyOptions
    | AzureEncryptionKeyOptions
    | GCPEncryptionKeyOptions
    | undefined;

  /**
   * An optional list of string alternate names used to reference a key.
   * If a key is created with alternate names, then encryption may refer to the key by the unique alternate name instead of by _id.
   */
  keyAltNames?: string[] | undefined;

  /** @experimental */
  keyMaterial?: Buffer | Binary;
}

/** @experimental */
export interface ClientEncryptionRewrapManyDataKeyProviderOptions {
  provider: ClientEncryptionDataKeyProvider;
  masterKey?:
    | AWSEncryptionKeyOptions
    | AzureEncryptionKeyOptions
    | GCPEncryptionKeyOptions
    | undefined;
}

/** @experimental */
export interface ClientEncryptionRewrapManyDataKeyResult {
  /** The result of rewrapping data keys. If unset, no keys matched the filter. */
  bulkWriteResult?: BulkWriteResult;
}

/**
 * RangeOptions specifies index options for a Queryable Encryption field supporting "rangePreview" queries.
 * min, max, sparsity, and range must match the values set in the encryptedFields of the destination collection.
 * For double and decimal128, min/max/precision must all be set, or all be unset.
 */
interface RangeOptions {
  min?: any;
  max?: any;
  sparsity: Long;
  precision?: number;
}

/**
 * Options to provide when encrypting data.
 */
export interface ClientEncryptionEncryptOptions {
  /**
   * The algorithm to use for encryption.
   */
  algorithm:
    | 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
    | 'AEAD_AES_256_CBC_HMAC_SHA_512-Random'
    | 'Indexed'
    | 'Unindexed'
    | 'RangePreview';

  /**
   * The id of the Binary dataKey to use for encryption
   */
  keyId?: Binary;

  /**
   * A unique string name corresponding to an already existing dataKey.
   */
  keyAltName?: string;

  /** The contention factor. */
  contentionFactor?: bigint | number;

  /**
   * The query type supported.  Only the queryType `equality` is stable.
   *
   * @experimental Public Technical Preview: The queryType `rangePreview` is experimental.
   */
  queryType?: 'equality' | 'rangePreview';

  /** @experimental Public Technical Preview: The index options for a Queryable Encryption field supporting "rangePreview" queries.*/
  rangeOptions?: RangeOptions;
}

/**
 * The public interface for explicit in-use encryption
 */
export class ClientEncryption {
  /**
   * Create a new encryption instance.
   * @param client The client used for encryption
   * @param options Additional settings
   */
  constructor(client: MongoClient, options: ClientEncryptionOptions);

  /**
   * Creates a data key used for explicit encryption and inserts it into the key vault namespace
   * @param provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
   */
  createDataKey(provider: ClientEncryptionDataKeyProvider): Promise<Binary>;

  /**
   * Creates a data key used for explicit encryption and inserts it into the key vault namespace
   * @param provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
   * @param options Options for creating the data key
   */
  createDataKey(
    provider: ClientEncryptionDataKeyProvider,
    options: ClientEncryptionCreateDataKeyProviderOptions
  ): Promise<Binary>;

  /**
   * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
   * use the Promise overloads instead.
   *
   * Creates a data key used for explicit encryption and inserts it into the key vault namespace
   * @param provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
   * @param callback Callback to invoke when key is created
   */
  createDataKey(
    provider: ClientEncryptionDataKeyProvider,
    callback: ClientEncryptionCreateDataKeyCallback
  ): void;

  /**
   * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
   * use the Promise overloads instead.
   *
   * Creates a data key used for explicit encryption and inserts it into the key vault namespace
   * @param provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
   * @param options Options for creating the data key
   * @param callback Callback to invoke when key is created
   */
  createDataKey(
    provider: ClientEncryptionDataKeyProvider,
    options: ClientEncryptionCreateDataKeyProviderOptions,
    callback: ClientEncryptionCreateDataKeyCallback
  ): void;

  /**
   * Searches the keyvault for any data keys matching the provided filter.  If there are matches, rewrapManyDataKey then attempts to re-wrap the data keys using the provided options.
   *
   * If no matches are found, then no bulk write is performed.
   */
  rewrapManyDataKey(
    filter: Document,
    options?: ClientEncryptionRewrapManyDataKeyProviderOptions
  ): Promise<ClientEncryptionRewrapManyDataKeyResult>;

  /**
   * Deletes the key with the provided id from the keyvault, if it exists.
   *
   * @param id - the id of the document to delete.
   */
  deleteKey(id: Binary): Promise<DeleteResult>;

  /**
   * Finds all the keys currently stored in the keyvault.
   *
   * This method will not throw.
   */
  getKeys(): FindCursor<DataKey>;

  /**
   * Finds a key in the keyvault with the specified key.
   *
   * @param id - the id of the document to delete.
   */
  getKey(id: Binary): Promise<DataKey | null>;

  /**
   * Finds a key in the keyvault which has the specified keyAltNames as a keyAltName.
   *
   * @param keyAltName - a potential keyAltName to search for in the keyAltNames array
   */
  getKeyByAltName(keyAltName: string): Promise<DataKey | null>;

  /**
   * Adds a keyAltName to a key identified by the provided `id`.
   *
   * This method resolves to/returns the *old* key value (prior to adding the new altKeyName).
   *
   * @param id - The id of the document to update.
   * @param keyAltName - a keyAltName to search for a key
   */
  addKeyAltName(id: Binary, keyAltName: string): Promise<DataKey | null>;

  /**
   * Adds a keyAltName to a key identified by the provided `id`.
   *
   * This method resolves to/returns the *old* key value (prior to removing the new altKeyName).
   *
   * If the removed keyAltName is the last keyAltName for that key, the `altKeyNames` property is unset from the document.
   *
   * @param id - the id of the document to update.
   * @param keyAltName - a keyAltName to search for a key
   */
  removeKeyAltName(id: Binary, keyAltName: string): Promise<DataKey | null>;

  /**
   * A convenience method for creating an encrypted collection.
   * This method will create data keys for any encryptedFields that do not have a `keyId` defined
   * and then create a new collection with the full set of encryptedFields.
   *
   * @param db - A Node.js driver Db object with which to create the collection
   * @param name - The name of the new collection
   * @param options - Options for createDataKey and for createCollection. A provider and partially created encryptedFields **must** be provided.
   * @throws {MongoCryptCreateDataKeyForEncryptedCollectionError} - If part way through the process a createDataKey invocation fails, an error will be rejected that has the partial `encryptedFields` that were created.
   * @throws {MongoCryptCreateEncryptedCollectionError} - If creating the collection fails, an error will be rejected that has the entire `encryptedFields` that were created.
   */
  createEncryptedCollection<TSchema extends Document = Document>(
    db: Db,
    name: string,
    options: {
      provider: ClientEncryptionDataKeyProvider;
      createCollectionOptions: Omit<CreateCollectionOptions, 'encryptedFields'> & {
        encryptedFields: Document;
      };
      masterKey?: AWSEncryptionKeyOptions | AzureEncryptionKeyOptions | GCPEncryptionKeyOptions;
    }
  ): Promise<{ collection: Collection<TSchema>; encryptedFields: Document }>;

  /**
   * Explicitly encrypt a provided value.
   * Note that either options.keyId or options.keyAltName must be specified.
   * Specifying both options.keyId and options.keyAltName is considered an error.
   * @param value The value that you wish to serialize. Must be of a type that can be serialized into BSON
   * @param options
   */
  encrypt(value: any, options: ClientEncryptionEncryptOptions): Promise<Binary>;

  /**
   * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
   * use the Promise overloads instead.
   *
   * Explicitly encrypt a provided value.
   * Note that either options.keyId or options.keyAltName must be specified.
   * Specifying both options.keyId and options.keyAltName is considered an error.
   * @param value The value that you wish to serialize. Must be of a type that can be serialized into BSON
   * @param options
   * @param callback Callback to invoke when value is encrypted
   */
  encrypt(
    value: any,
    options: ClientEncryptionEncryptOptions,
    callback: ClientEncryptionEncryptCallback
  ): void;

  /**
   * Encrypts a Match Expression or Aggregate Expression to query a range index.
   *
   * Only supported when queryType is "rangePreview" and algorithm is "RangePreview".
   *
   * @experimental The Range algorithm is experimental only. It is not intended for production use. It is subject to breaking changes.The aggregation or match expression you wish to encrypt.  The value must be in the form
   *
   * The expression to encrypt must be one of the following:
   *  1. A Match Expression of this form:
   *      `{$and: [{<field>: {$gt: <value1>}}, {<field>: {$lt: <value2> }}]}`
   *  2. An Aggregate Expression of this form:
   *      `{$and: [{$gt: [<fieldpath>, <value1>]}, {$lt: [<fieldpath>, <value2>]}]}`
   *
   *    `$gt` may also be `$gte`. `$lt` may also be `$lte`.
   */
  encryptExpression(value: Document, options: ClientEncryptionEncryptOptions): Promise<Document>;

  /**
   * Explicitly decrypt a provided encrypted value
   * @param value An encrypted value
   */
  decrypt(value: Buffer | Binary): Promise<any>;

  /**
   * @deprecated Callback overloads are deprecated and will be removed in the next major version.  Please
   * use the Promise overloads instead.
   *
   * Explicitly decrypt a provided encrypted value
   * @param value An encrypted value
   * @param callback Callback to invoke when value is decrypted
   */
  decrypt(value: Buffer | Binary, callback: ClientEncryptionDecryptCallback): void;

  static readonly libmongocryptVersion: string;
}
