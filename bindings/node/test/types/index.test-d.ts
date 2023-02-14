import { expectAssignable, expectError, expectType } from 'tsd';
import { RangeOptions, AWSEncryptionKeyOptions, AzureEncryptionKeyOptions, ClientEncryption, GCPEncryptionKeyOptions, ClientEncryptionEncryptOptions } from '../..';

type RequiredCreateEncryptedCollectionSettings = Parameters<
  ClientEncryption['createEncryptedCollection']
>[2];

expectError<RequiredCreateEncryptedCollectionSettings>({});
expectError<RequiredCreateEncryptedCollectionSettings>({
  provider: 'blah!',
  createCollectionOptions: { encryptedFields: {} }
});
expectError<RequiredCreateEncryptedCollectionSettings>({
  provider: 'aws',
  createCollectionOptions: {}
});
expectError<RequiredCreateEncryptedCollectionSettings>({
  provider: 'aws',
  createCollectionOptions: { encryptedFields: null }
});

expectAssignable<RequiredCreateEncryptedCollectionSettings>({
  provider: 'aws',
  createCollectionOptions: { encryptedFields: {} }
});
expectAssignable<RequiredCreateEncryptedCollectionSettings>({
  provider: 'aws',
  createCollectionOptions: { encryptedFields: {} },
  masterKey: { } as AWSEncryptionKeyOptions | AzureEncryptionKeyOptions | GCPEncryptionKeyOptions
});

{
  // NODE-5041 - incorrect spelling of rangeOpts in typescript definitions
  const options = {} as ClientEncryptionEncryptOptions;
  expectType<RangeOptions | undefined>(options.rangeOptions)
}
