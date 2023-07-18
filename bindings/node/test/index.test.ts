import { expect } from 'chai';
import { MongoCrypt } from '../src/index';

describe('index.ts', () => {
  it('exports a class MongoCrypt', () => {
    expect(MongoCrypt).to.exist;
  });
});
