import { readFile } from 'node:fs/promises'
import Module from 'node:module'
import { dirname, resolve } from 'node:path'

let distInternalsPromise

function addKeyAgreementTestHooks(source) {
  source = source.replaceAll(
    'validateKeyByAlgCode3(',
    '__validateKeyByAlgCode3('
  )
  source = source.replace(
    'function __validateKeyByAlgCode3(key) {',
    'function validateKeyByAlgCode3(key) {'
  )
  return source.replace(
    '// src/KeyAgreement/.core/helpers/createImportKeyAlgorithmByAlgCode/index.ts',
    [
      'let __validateKeyByAlgCode3 = validateKeyByAlgCode3;',
      'function setKeyAgreementValidateKeyByAlgCodeForTest(fn) {',
      '  __validateKeyByAlgCode3 = fn;',
      '}',
      'function resetKeyAgreementValidateKeyByAlgCodeForTest() {',
      '  __validateKeyByAlgCode3 = validateKeyByAlgCode3;',
      '}',
      '',
      '// src/KeyAgreement/.core/helpers/createImportKeyAlgorithmByAlgCode/index.ts',
    ].join('\n')
  )
}

function addDigitalSignatureTestHooks(source) {
  source = source.replaceAll(
    'validateKeyByAlgCode4(',
    '__validateKeyByAlgCode4('
  )
  source = source.replace(
    'function __validateKeyByAlgCode4(key) {',
    'function validateKeyByAlgCode4(key) {'
  )
  return source.replace(
    '// src/DigitalSignature/.core/SignKeyHarness/class.ts',
    [
      'let __validateKeyByAlgCode4 = validateKeyByAlgCode4;',
      'function setDigitalSignatureValidateKeyByAlgCodeForTest(fn) {',
      '  __validateKeyByAlgCode4 = fn;',
      '}',
      'function resetDigitalSignatureValidateKeyByAlgCodeForTest() {',
      '  __validateKeyByAlgCode4 = validateKeyByAlgCode4;',
      '}',
      '',
      '// src/DigitalSignature/.core/SignKeyHarness/class.ts',
    ].join('\n')
  )
}

function exposeInternals(source) {
  return [
    source,
    '',
    'module.exports.__internals = {',
    '  Cryptographic,',
    '  CryptosuiteError,',
    '  getBufferSourceLength,',
    '  validateCipherKeyByAlgCodeInternal: validateKeyByAlgCode,',
    '  createCipherParamsByAlgCodeInternal: createParamsByAlgCode,',
    '  getCipherParamsByAlgCodeInternal: getParamsByAlgCode,',
    '  getCipherImportKeyAlgorithmByAlgCodeInternal: getImportKeyAlgorithmByAlgCode,',
    '  CipherKeyHarness,',
    '  validateMessageAuthenticationKeyByAlgCodeInternal: validateKeyByAlgCode2,',
    '  createMessageAuthenticationImportKeyAlgorithmByAlgCodeInternal: createImportKeyAlgorithmByAlgCode,',
    '  createMessageAuthenticationParamsByAlgCodeInternal: createParamsByAlgCode2,',
    '  getMessageAuthenticationParamsByAlgCodeInternal: getParamsByAlgCode2,',
    '  MessageAuthenticationKeyHarness,',
    '  validateKeyAgreementKeyByAlgCodeInternal: validateKeyByAlgCode3,',
    '  createKeyAgreementImportKeyAlgorithmByAlgCodeInternal: createImportKeyAlgorithmByAlgCode2,',
    '  createKeyAgreementParamsByAlgCodeInternal: createParamsByAlgCode3,',
    '  getKeyAgreementParamsByAlgCodeInternal: getParamsByAlgCode3,',
    '  EncapsulateKeyHarness,',
    '  DecapsulateKeyHarness,',
    '  generateKeyAgreementKeypair,',
    '  deriveKeyAgreementKeypair,',
    '  setKeyAgreementValidateKeyByAlgCodeForTest,',
    '  resetKeyAgreementValidateKeyByAlgCodeForTest,',
    '  validateDigitalSignatureKeyByAlgCodeInternal: validateKeyByAlgCode4,',
    '  createDigitalSignatureImportKeyAlgorithmByAlgCodeInternal: createImportKeyAlgorithmByAlgCode3,',
    '  createDigitalSignatureParamsByAlgCodeInternal: createParamsByAlgCode4,',
    '  getDigitalSignatureParamsByAlgCodeInternal: getParamsByAlgCode4,',
    '  SignKeyHarness,',
    '  VerifyKeyHarness,',
    '  generateDigitalSignatureKeypair,',
    '  deriveDigitalSignatureKeypair,',
    '  setDigitalSignatureValidateKeyByAlgCodeForTest,',
    '  resetDigitalSignatureValidateKeyByAlgCodeForTest,',
    '};',
    '',
  ].join('\n')
}

export async function loadDistInternals() {
  distInternalsPromise ??= (async () => {
    const filename = resolve('dist/index.cjs')
    let source = await readFile(filename, 'utf8')
    source = addKeyAgreementTestHooks(source)
    source = addDigitalSignatureTestHooks(source)
    source = exposeInternals(source)

    const module = new Module(filename)
    module.filename = filename
    module.paths = Module._nodeModulePaths(dirname(filename))
    module._compile(source, filename)
    return module.exports.__internals
  })()

  return await distInternalsPromise
}
