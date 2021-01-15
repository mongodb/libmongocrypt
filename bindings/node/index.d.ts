import type { Binary } from 'bson';
import type { MongoClient } from 'mongodb';

export type ClientEncryptionDataKeyProvider = 'aws' | 'azure' | 'gcp' | 'local';

/**
 * An error indicating that something went wrong specifically with MongoDB Client Encryption
 */
export class MongoCryptError extends Error {
}

export interface ClientEncryptionCreateDataKeyCallback {
  /**
   * @param error If present, indicates an error that occurred in the creation of the data key
   * @param dataKeyId If present, returns the id of the created data key
   */
  (error?: Error, dataKeyId?: Binary): void;
}

export interface ClientEncryptionEncryptCallback {
  /**
   * @param error If present, indicates an error that occurred in the process of encryption
   * @param result If present, is the encrypted result
   */
  (error?: Error, result?: Binary): void;
}

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
  aws?: {
    /**
     * The access key used for the AWS KMS provider
     */
    accessKeyId?: string | undefined;

    /**
     * The secret access key used for the AWS KMS provider
     */
    secretAccessKey?: string | undefined;
  };

  /**
   * Configuration options for using 'local' as your KMS provider
   */
  local?: {
    /**
     * The master key used to encrypt/decrypt data keys. A 96-byte long Buffer.
     */
    key?: Buffer | undefined;
  };

  /**
   * Configuration options for using 'azure' as your KMS provider
   */
  azure?: {
    /**
     * The tenant ID identifies the organization for the account
     */
    tenantId?: string | undefined;

    /**
     * The client ID to authenticate a registered application
     */
    clientId?: string | undefined;

    /**
     * The client secret to authenticate a registered application
     */
    clientSecret?: string | undefined;

    /**
     * If present, a host with optional port. E.g. "example.com" or "example.com:443".
     * This is optional, and only needed if customer is using a non-commercial Azure instance
     * (e.g. a government or China account, which use different URLs).
     * Defaults to "login.microsoftonline.com"
     */
    identityPlatformEndpoint?: string | undefined;
  };
  
  /**
   * Configuration options for using 'gcp' as your KMS provider
   */
  gcp?: {
    /**
     * The service account email to authenticate
     */
    email?: string | undefined;

    /**
     * A PKCS#8 encrypted key. This can either be a base64 string or a binary representation
     */
    privateKey?: string | Buffer | undefined;

    /**
     * If present, a host with optional port. E.g. "example.com" or "example.com:443".
     * Defaults to "oauth2.googleapis.com"
     */
    endpoint?: string | undefined;
  }
}

/**
 * Optional settings to provide when creating a new `ClientEncryption` instance.
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
  kmsProviders?: KMSProviders | undefined;
}

/**
 * Configuration options for making an AWS encryption key
 */
export interface AWSEncryptionKeyOptions {
  /**
   * The AWS region of the KMS
   */
  region?: string | undefined;

  /**
   * The Amazon Resource Name (ARN) to the AWS customer master key (CMK)
   */
  key?: string | undefined;

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
  projectId?: string | undefined;

  /**
   * Location name (e.g. "global")
   */
  location?: string | undefined;

  /**
   * Key ring name
   */
  keyRing?: string | undefined;

  /**
   * Key name
   */
  keyName?: string | undefined;

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
  keyName?: string | undefined;

  /**
   * Key version
   */
  keyVersion?: string | undefined;

  /**
   * Key vault URL, typically `<name>.vault.azure.net`
   */
  keyVaultEndpoint?: string | undefined;
}

/**
 * Options to provide when creating a new data key.
 */
export interface ClientEncryptionCreateDataKeyProviderOptions {
  /**
   * Idenfities a new KMS-specific key used to encrypt the new data key
   */
  masterKey?: AWSEncryptionKeyOptions | AzureEncryptionKeyOptions | GCPEncryptionKeyOptions | undefined;

  /**
   * An optional list of string alternate names used to reference a key.
   * If a key is created with alternate names, then encryption may refer to the key by the unique alternate name instead of by _id.
   */
  keyAltNames?: string[] | undefined;
}

/**
 * Options to provide when encrypting data.
 */
export interface ClientEncryptionEncryptOptions {
  /**
   * The algorithm to use for encryption.
   */
  algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic' | 'AEAD_AES_256_CBC_HMAC_SHA_512-Random';

  /**
   * The id of the Binary dataKey to use for encryption
   */
  keyId?: Binary | undefined;

  /**
   * A unique string name corresponding to an already existing dataKey.
   */
  keyAltName?: string | undefined;
}

/**
 * The public interface for explicit client side encrption.
 */
export class ClientEncryption {
  /**
   * Create a new encryption instance.
   * @param client The client used for encryption
   * @param options Optional settings
   */
  constructor(client: MongoClient, options?: ClientEncryptionOptions);

  /**
   * Creates a data key used for explicit encryption and inserts it into the key vault namespace
   * @param provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
   */
  createDataKey(
    provider: ClientEncryptionDataKeyProvider
  ): Promise<Binary>;

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
   * Creates a data key used for explicit encryption and inserts it into the key vault namespace
   * @param provider The KMS provider used for this data key. Must be `'aws'`, `'azure'`, `'gcp'`, or `'local'`
   * @param callback Callback to invoke when key is created
   */
  createDataKey(
    provider: ClientEncryptionDataKeyProvider,
    callback: ClientEncryptionCreateDataKeyCallback
  ): void;

  /**
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
   * Explicitly encrypt a provided value.
   * Note that either options.keyId or options.keyAltName must be specified.
   * Specifying both options.keyId and options.keyAltName is considered an error.
   * @param value The value that you wish to serialize. Must be of a type that can be serialized into BSON
   * @param options
   */
  encrypt(
    value: any,
    options: ClientEncryptionEncryptOptions
  ): Promise<Binary>;

  /**
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
   * Explicitly decrypt a provided encrypted value
   * @param value An encrypted value
   */
  decrypt(
    value: Binary
  ): Promise<any>;

  /**
   * Explicitly decrypt a provided encrypted value
   * @param value An encrypted value
   * @param callback Callback to invoke when value is decrypted
   */
  decrypt(
    value: Binary,
    callback: ClientEncryptionDecryptCallback
  ): void;
}
