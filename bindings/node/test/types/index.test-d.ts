import { expectAssignable, expectError } from 'tsd';
import { ClientEncryption } from '../..';

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
  createDataKeyOptions: {}
});
