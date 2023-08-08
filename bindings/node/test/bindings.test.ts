import { expect } from 'chai';
import { MongoCrypt, MongoCryptContextCtor } from '../src';
import { serialize, Binary, Long } from 'bson';
import * as crypto from 'crypto';

// the `randomHook` is necessary for some tests, so we copy it in here.
// if in the future we need more than just this crypto hook, we can
// consider bringing the hooks back into libmongocrypt from the driver.
export function randomHook(buffer: Buffer, count: number): number | Error {
  try {
    crypto.randomFillSync(buffer, 0, count);
  } catch (e) {
    return e;
  }
  return count;
}

describe('MongoCryptConstructor', () => {
  const mc = new MongoCrypt({
    kmsProviders: serialize({ aws: {} }),
    cryptoCallbacks: {
      aes256CbcEncryptHook: () => {},
      aes256CbcDecryptHook: () => {},
      aes256CtrEncryptHook: () => {},
      aes256CtrDecryptHook: () => {},
      randomHook,
      hmacSha512Hook: () => {},
      hmacSha256Hook: () => {},
      sha256Hook: () => {},
      signRsaSha256Hook: () => {}
    }
  });

  it('requires an options argument', () => {
    expect(() => new MongoCrypt()).to.throw(/First parameter must be an object/);
  });

  it('creates a MongoCrypt when provided valid options', () => {
    expect(
      new MongoCrypt({
        kmsProviders: serialize({ aws: {} }),
        schemaMap: serialize({}),
        encryptedFieldsMap: serialize({}),
        logger: () => {},
        cryptoCallbacks: {
          aes256CbcEncryptHook: () => {},
          aes256CbcDecryptHook: () => {},
          aes256CtrEncryptHook: () => {},
          aes256CtrDecryptHook: () => {},
          randomHook,
          hmacSha512Hook: () => {},
          hmacSha256Hook: () => {},
          sha256Hook: () => {},
          signRsaSha256Hook: () => {}
        },

        bypassQueryAnalysis: false
      })
    ).to.be.instanceOf(MongoCrypt);
  });

  it('has a static `libmongoCryptVersion` property', () => {
    expect(MongoCrypt).to.have.property('libmongocryptVersion').that.is.a.string;
  });

  describe('options.kmsProviders', () => {
    it('throws if provided and are not a Uint8Array', () => {
      expect(() => new MongoCrypt({ kmsProviders: 3 })).to.throw(
        /Parameter `options.kmsProviders` must be a Uint8Array./
      );
    });

    it('throws when explicitly set to undefined', () => {
      // the error is different because it is thrown from libmongocrypt
      expect(() => new MongoCrypt({ kmsProviders: undefined })).to.throw(/no kms provider set/);
    });
  });

  describe('options.schemaMap', () => {
    it('throws when provided and not a Uint8Array', () => {
      expect(
        () =>
          new MongoCrypt({
            kmsProviders: serialize({ aws: {} }),
            schemaMap: 3
          })
      ).to.throw(/Parameter `options.schemaMap` must be a Uint8Array./);
    });

    it('can be explicitly set to `undefined`', () => {
      expect(
        new MongoCrypt({
          kmsProviders: serialize({ aws: {} }),
          schemaMap: undefined
        })
      ).to.be.instanceOf(MongoCrypt);
    });
  });

  describe('options.encryptedFieldsMap', () => {
    it('throws when provided and not a Uint8Array', () => {
      expect(
        () =>
          new MongoCrypt({
            kmsProviders: serialize({ aws: {} }),
            encryptedFieldsMap: 3
          })
      ).to.throw(/Parameter `options.encryptedFieldsMap` must be a Uint8Array./);
    });

    it('can be explicitly set to `undefined`', () => {
      expect(
        new MongoCrypt({
          kmsProviders: serialize({ aws: {} }),
          encryptedFieldsMap: undefined
        })
      ).to.be.instanceOf(MongoCrypt);
    });
  });

  it('throws when cryptSharedLibSearchPaths is not an array', () => {
    expect(
      () =>
        new MongoCrypt({
          kmsProviders: serialize({ aws: {} }),
          cryptSharedLibSearchPaths: 3
        })
    ).to.throw(/Option `cryptSharedLibSearchPaths` must be an array/);
  });

  it('has an instance property `status`', () => {
    const mc = new MongoCrypt({ kmsProviders: serialize({ aws: {} }) });
    expect(mc).to.have.property('status');
    expect(mc).to.have.property('cryptSharedLibVersionInfo');
  });

  describe('.makeEncryptionContext()', () => {
    it('throws if `command` is not a Uint8Array', () => {
      expect(() => mc.makeEncryptionContext('foo.bar', 'some non-buffer')).to.throw(
        /Parameter `command` must be a Uint8Array./
      );
    });

    it('returns a MongoCryptContext', () => {
      expect(mc.makeEncryptionContext('foo.bar', serialize({ ping: 1 }))).to.be.instanceOf(
        MongoCryptContextCtor
      );
    });
  });

  describe('.makeDecryptionContext()', () => {
    it('throws if not provided a Uint8Array', () => {
      expect(() => mc.makeDecryptionContext('foo.bar')).to.throw(
        /Parameter `value` must be a Uint8Array./
      );
    });

    it('returns a MongoCryptContext', () => {
      expect(mc.makeDecryptionContext(serialize({ ping: 1 }))).to.be.instanceOf(
        MongoCryptContextCtor
      );
    });
  });

  describe('.makeExplicitDecryptionContext()', () => {
    it('throws if not provided a Uint8Array', () => {
      expect(() => mc.makeExplicitDecryptionContext('foo.bar')).to.throw(
        /Parameter `value` must be a Uint8Array./
      );
    });

    it('returns a MongoCryptContext', () => {
      expect(
        mc.makeExplicitDecryptionContext(serialize({ v: new Binary(Buffer.from([]), 6) }))
      ).to.be.instanceOf(MongoCryptContextCtor);
    });
  });

  describe('.makeRewrapManyDataKeyContext()', () => {
    it('returns a MongoCryptContext', () => {
      expect(mc.makeRewrapManyDataKeyContext(serialize({}))).to.be.instanceOf(
        MongoCryptContextCtor
      );
    });

    describe('when a filter buffer is provided', () => {
      it('throws when the filter is not a Uint8Array', () => {
        expect(() => mc.makeRewrapManyDataKeyContext('foo.bar')).to.throw(
          /Parameter `filter` must be a Uint8Array./
        );
      });

      it('can be explicitly passed `undefined`', () => {
        expect(mc.makeRewrapManyDataKeyContext(serialize({}), undefined)).to.be.instanceOf(
          MongoCryptContextCtor
        );
      });
    });
  });

  describe('.makeDataKeyContext()', () => {
    const providers = serialize({
      provider: 'aws',
      region: 'region',
      key: 'key'
    });
    it('returns a MongoCryptContext', () => {
      expect(mc.makeDataKeyContext(providers, {})).to.be.instanceOf(MongoCryptContextCtor);
    });

    it('throws when the first parameter is not a Uint8Array', () => {
      expect(() => mc.makeDataKeyContext('foo.bar', {})).to.throw(
        /Parameter `options` must be a Uint8Array./
      );
    });

    describe('options.keyAltNames', () => {
      it('can be explicitly set to `undefined`', () => {
        expect(
          mc.makeDataKeyContext(providers, {
            keyAltNames: undefined
          })
        ).to.be.instanceOf(MongoCryptContextCtor);
      });

      it('throws a TypeError when options.keyAltNames includes values that are not Uint8Arrays', () => {
        expect(() =>
          mc.makeDataKeyContext(providers, {
            keyAltNames: [1]
          })
        )
          .to.throw(/Parameter `options.keyAltName\[\]` must be a Uint8Array./)
          .to.be.instanceOf(TypeError);
      });
    });

    describe('options.keyMaterial', () => {
      it('can be explicitly set to `undefined`', () => {
        expect(
          mc.makeDataKeyContext(providers, {
            keyMaterial: undefined
          })
        ).to.be.instanceOf(MongoCryptContextCtor);
      });

      it('throws a TypeError when provided and is not a Uint8Array', () => {
        expect(() =>
          mc.makeDataKeyContext(providers, {
            keyMaterial: 'foo bar baz'
          })
        )
          .to.throw(/Parameter `options.keyMaterial` must be a Uint8Array./)
          .to.be.instanceOf(TypeError);
      });
    });
  });

  describe('.makeExplicitEncryptionContext()', () => {
    const value = serialize({ v: 'something to serialize' });
    const keyId = new Binary(Buffer.alloc(16), 6);

    it('returns a `MongoCryptContext`', () => {
      expect(
        mc.makeExplicitEncryptionContext(value, {
          // minimum required arguments from libmongocrypt
          keyId: keyId.buffer,
          expressionMode: false,
          algorithm: 'Unindexed'
        })
      ).to.be.instanceOf(MongoCryptContextCtor);
    });

    it('throws a TypeError when `value` is not a Uint8Array', () => {
      expect(() =>
        mc.makeExplicitEncryptionContext('asdf', {
          // minimum required arguments from libmongocrypt
          keyId: keyId.buffer,
          expressionMode: false,
          algorithm: 'Unindexed'
        })
      )
        .to.throw(/Parameter `value` must be a Uint8Array./)
        .to.be.instanceOf(TypeError);
    });

    describe('options.keyId', () => {
      it('throws a TypeError when provided and is not a Uint8Array', () => {
        expect(() =>
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyId: 'asdf',
            expressionMode: false,
            algorithm: 'Unindexed'
          })
        )
          .to.throw(/Parameter `keyId` must be a Uint8Array./)
          .to.be.instanceOf(TypeError);
      });

      it('throws a TypeError when explicitly set to `undefined`', () => {
        expect(() =>
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyId: undefined,
            expressionMode: false,
            algorithm: 'Unindexed'
          })
        )
          // error thrown from `libmongocrypt`
          .to.throw(/either key id or key alt name required/)
          .to.be.instanceOf(TypeError);
      });
    });

    describe('options.keyAltName', () => {
      it('throws a TypeError provided and is not a Uint8Array', () => {
        expect(() =>
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyAltName: 'asdf',
            expressionMode: false,
            algorithm: 'Unindexed'
          })
        )
          .to.throw(/Parameter `keyAltName` must be a Uint8Array./)
          .to.be.instanceOf(TypeError);
      });

      it('throws a TypeError when explicitly set to `undefined`', () => {
        expect(() =>
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyAltName: undefined,
            expressionMode: false,
            algorithm: 'Unindexed'
          })
        )
          // error thrown from `libmongocrypt`
          .to.throw(/either key id or key alt name required/)
          .to.be.instanceOf(TypeError);
      });
    });

    context('when algorithm is `rangePreview', () => {
      it('throws a TypeError if rangeOptions is not provided', () => {
        expect(() =>
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyId: keyId.buffer,
            expressionMode: false,
            algorithm: 'rangePreview'
          })
        )
          .to.throw(/`rangeOptions` must be provided if `algorithm` is set to RangePreview/)
          .to.be.instanceOf(TypeError);
      });

      it('throws a TypeError if `rangeOptions` is not a Uint8Array', () => {
        expect(() =>
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyId: keyId.buffer,
            expressionMode: false,
            algorithm: 'rangePreview',
            rangeOptions: 'non-buffer'
          })
        )
          .to.throw(/Parameter `rangeOptions` must be a Uint8Array./)
          .to.be.instanceOf(TypeError);
      });

      it('checks if `rangePreview` is set case-insensitive', () => {
        expect(
          mc.makeExplicitEncryptionContext(value, {
            // minimum required arguments from libmongocrypt
            keyId: keyId.buffer,
            expressionMode: false,
            algorithm: 'RANGEPREVIEW',
            rangeOptions: serialize({
              sparsity: new Long(42)
            }),

            // contention factor is required for `rangePreview` but
            // is enforced in libmongocrypt, not our bindings
            contentionFactor: 2
          })
        ).to.be.instanceOf(MongoCryptContextCtor);
      });
    });
  });
});

describe('MongoCryptContext', () => {
  const context = new MongoCrypt({
    kmsProviders: serialize({ aws: {} })
  }).makeDecryptionContext(serialize({}));

  for (const property of ['status', 'state']) {
    it(`it has a property .${property}`, () => {
      expect(context).to.have.property(property);
    });
  }

  for (const method of [
    'nextMongoOperation',
    'addMongoOperationResponse',
    'finishMongoOperation',
    'nextKMSRequest',
    'provideKMSProviders',
    'finishKMSRequests',
    'finalize'
  ]) {
    it(`it has a method .${method}()`, () => {
      expect(context).to.have.property(method).that.is.a('function');
    });
  }

  describe('addMongoOperationResponse', () => {
    it('throws if called with a non-Uint8Array', () => {
      expect(() => context.addMongoOperationResponse({}))
        .to.throw(/Parameter `buffer` must be a Uint8Array./)
        .to.be.instanceOf(TypeError);
    });

    it('succeeds when called with a Uint8Array', () => {
      expect(() =>
        context.addMongoOperationResponse(new Uint8Array(Buffer.from([1, 2, 3])))
      ).not.to.throw();
    });
  });
});
