import { expect } from 'chai';
import * as bindings from '../src/index';

describe('index.ts', () => {
  it('only has one export', () => {
    expect(Object.keys(bindings).length).to.equal(2);
  });

  it('exports a class MongoCrypt', () => {
    expect(bindings).to.have.property('MongoCrypt');
  });

  it('exposes MongoCryptContextCtor', () => {
    expect(bindings).to.have.property('MongoCryptContextCtor');
  });

  it('exposes MongoCryptKMSRequestCtor', () => {
    expect(bindings).not.to.have.property('MongoCryptKMSRequestCtor');
  });
});
