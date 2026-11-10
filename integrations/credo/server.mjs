import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash, createPrivateKey, timingSafeEqual, X509Certificate as NativeCertificate } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { createServer } from 'node:https';
import { isIP } from 'node:net';
import { isAbsolute } from 'node:path';
import { Agent, ConsoleLogger, LogLevel, X509Certificate } from '@credo-ts/core';
import { KeyManagementModule } from '@credo-ts/core/kms';
import { AskarModule } from '@credo-ts/askar';
import { agentDependencies, NodeInMemoryKeyManagementStorage, NodeKeyManagementService } from '@credo-ts/node';
import { OpenId4VcModule } from '@credo-ts/openid4vc';
import { NativeAskar } from '@openwallet-foundation/askar-nodejs';
import express from 'express';
import { createTransientStore } from './storage.mjs';

const verifierId = 'proofsieve';
const walletBase = '/oid4vp';
const authorizationPath = walletBase + '/' + verifierId + '/authorize';
const requestPrefix = walletBase + '/' + verifierId + '/authorization-requests/';
const internalBase = '/internal/proofsieve/wallet/transactions';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const noncePattern = /^[A-Za-z0-9_-]{16,128}$/;
const tokenPattern = /^[A-Za-z0-9_-]{43,128}$/;
const jwePattern = /^([A-Za-z0-9_-]{2,4096})\.\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]+\.([A-Za-z0-9_-]{22})$/;
const gcmAlgorithms = ['A128GCM', 'A192GCM', 'A256GCM'];
const statusFormat = 'dc+sd-jwt';
const mdocFormat = 'mso_mdoc';
const maxPresentation = 192 * 1024;
const maxBridgeResponse = 256 * 1024;
const ttlSeconds = 300;
const maxSessions = 128;
const context = new AsyncLocalStorage();

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function keys(value, names) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name));
}

function acceptsEncryptedResponse(value, entry) {
  const parts = typeof value === 'string' && jwePattern.exec(value);
  if (!parts) return false;
  const [, protectedHeader, tag] = parts;
  const raw = Buffer.from(protectedHeader, 'base64url');
  if (raw.toString('base64url') !== protectedHeader || Buffer.from(tag, 'base64url').toString('base64url') !== tag) return false;
  try {
    const { alg, enc, epk } = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw));
    return alg === 'ECDH-ES' && entry.responseEncryption.includes(enc)
      && epk?.kty === 'EC' && epk.crv === entry.encryptionCurve && !Object.hasOwn(epk, 'd')
      && [epk.x, epk.y].every(coordinate => typeof coordinate === 'string'
        && /^[A-Za-z0-9_-]+$/.test(coordinate) && coordinate.length === entry.coordinateLength);
  } catch {
    return false;
  }
}

function localFile(path, privateFile = false) {
  assert(typeof path === 'string' && isAbsolute(path), 'Use absolute configuration paths');
  const file = statSync(path);
  assert(file.isFile() && file.size > 0 && file.size <= 128 * 1024, 'Configuration file outside size limit');
  if (privateFile) {
    assert(file.uid === process.getuid() && (file.mode & 0o077) === 0, 'Private configuration and key files must be owner-only');
  }
  return readFileSync(path, 'utf8');
}

function certificates(pem) {
  assert(typeof pem === 'string' && pem.length <= 32 * 1024, 'Invalid issuer certificate chain');
  const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  assert(blocks.length >= 1 && blocks.length <= 8 && !pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim(),
    'Invalid issuer certificate chain');
  return blocks.map((block) => new NativeCertificate(block).raw.toString('base64'));
}

function readConfig(path) {
  const config = JSON.parse(localFile(path, true));
  const required = ['publicOrigin', 'publicHost', 'publicPort', 'privatePort', 'tlsCertFile', 'tlsKeyFile',
    'verifierCertFile', 'verifierKeyFile', 'intendedUseId', 'bearerEnv'];
  assert(keys(config, required) || keys(config, [...required, 'verifierChainFile']), 'Invalid Credo bridge configuration');
  const origin = new URL(config.publicOrigin);
  assert(origin.protocol === 'https:' && origin.origin === config.publicOrigin, 'Use a bare HTTPS public origin');
  assert(isIP(config.publicHost), 'Use an explicit public listener IP address');
  for (const port of [config.privatePort, config.publicPort]) {
    assert(Number.isInteger(port) && port > 1023 && port <= 65535, 'Use unprivileged listener ports');
  }
  assert(config.privatePort !== config.publicPort, 'Use separate private and public ports');
  assert(typeof config.intendedUseId === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(config.intendedUseId), 'Invalid intended use identifier');
  assert(typeof config.bearerEnv === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/.test(config.bearerEnv), 'Invalid bearer environment name');
  const token = process.env[config.bearerEnv];
  assert(tokenPattern.test(token ?? ''), 'Configure a dedicated private service bearer');
  const verifierPem = localFile(config.verifierCertFile);
  const verifierCert = new NativeCertificate(verifierPem);
  const verifierKey = createPrivateKey(localFile(config.verifierKeyFile, true));
  assert(verifierCert.checkPrivateKey(verifierKey) && verifierKey.asymmetricKeyDetails?.namedCurve === 'prime256v1',
    'Use a matching P-256 verifier certificate and private key');
  assert(!verifierCert.ca && Date.parse(verifierCert.validFrom) <= Date.now() && Date.now() < Date.parse(verifierCert.validTo),
    'Use a currently valid verifier leaf certificate');
  return {
    ...config,
    bearer: Buffer.from('Bearer ' + token),
    tls: { cert: localFile(config.tlsCertFile), key: localFile(config.tlsKeyFile, true), minVersion: 'TLSv1.2' },
    verifierJwk: verifierKey.export({ format: 'jwk' }),
    verifierCertificates: [verifierCert.raw.toString('base64'),
      ...(config.verifierChainFile ? certificates(localFile(config.verifierChainFile)) : [])],
    clientId: 'x509_hash:' + createHash('sha256').update(verifierCert.raw).digest('base64url'),
  };
}

function queryCredential(dcql) {
  assert(keys(dcql, ['credentials']) && Array.isArray(dcql.credentials) && dcql.credentials.length === 1, 'One DCQL credential required');
  const credential = dcql.credentials[0];
  assert(keys(credential, ['id', 'format', 'meta', 'require_cryptographic_holder_binding', 'claims'])
    && credential.id === 'credential' && credential.require_cryptographic_holder_binding === true
    && [statusFormat, mdocFormat].includes(credential.format) && Array.isArray(credential.claims)
    && credential.claims.length >= 1 && credential.claims.length <= 32, 'Unsupported DCQL query');
  for (const claim of credential.claims) {
    assert(keys(claim, ['path']) && Array.isArray(claim.path) && claim.path.length >= 1 && claim.path.length <= 8
      && typeof claim.path[0] === 'string'
      && claim.path.every((part) => typeof part === 'string' ? /^[A-Za-z0-9_.:/-]{1,256}$/.test(part)
        && !['__proto__', 'constructor', 'prototype'].includes(part) : Number.isSafeInteger(part) && part >= 0 && part <= 31),
    'Invalid DCQL claim path');
    if (credential.format === mdocFormat) assert(claim.path.length === 2 && typeof claim.path[1] === 'string', 'Invalid mdoc claim path');
  }
  if (credential.format === statusFormat) {
    assert(keys(credential.meta, ['vct_values']) && Array.isArray(credential.meta.vct_values)
      && credential.meta.vct_values.length === 1 && typeof credential.meta.vct_values[0] === 'string', 'One SD-JWT vct required');
  } else {
    assert(keys(credential.meta, ['doctype_value']) && typeof credential.meta.doctype_value === 'string', 'One mdoc doctype required');
  }
  return credential;
}

function bindServer(app, tls, host, port) {
  const server = createServer({ ...tls, requestTimeout: 15_000, headersTimeout: 10_000, maxHeaderSize: 8192 }, app);
  server.maxRequestsPerSocket = 32;
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve(server));
  });
}

function appWithSafeDefaults() {
  const app = express();
  app.disable('x-powered-by');
  app.set('query parser', 'simple');
  app.use((_req, res, next) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Content-Type-Options', 'nosniff');
    next();
  });
  return app;
}

function fixedError(res, status) {
  return res.status(status).json({ error: 'wallet_bridge_request_failed' });
}

async function start(config, store) {
  const byId = new Map();
  const byRequest = new Map();
  const inProgress = new Set();
  const publicApp = appWithSafeDefaults();
  const privateApp = appWithSafeDefaults();
  publicApp.use((req, res, next) => {
    if (req.method === 'GET' && req.originalUrl.startsWith(requestPrefix)) {
      const id = req.originalUrl.slice(requestPrefix.length);
      const entry = uuid.test(id) && byRequest.get(id);
      if (!entry || entry.expiresAt <= Date.now() || entry.finished) return fixedError(res, 404);
      return next();
    }
    if (req.method !== 'POST' || req.path !== authorizationPath || !req.is('application/x-www-form-urlencoded')) {
      return fixedError(res, 404);
    }
    const id = req.originalUrl.slice(authorizationPath.length + '?session='.length);
    if (req.originalUrl !== authorizationPath + '?session=' + id || !uuid.test(id)) return fixedError(res, 404);
    const entry = byRequest.get(id);
    if (!entry || entry.expiresAt <= Date.now()) return fixedError(res, 404);
    if (entry.finished || entry.processing) return fixedError(res, 409);
    req.walletEntry = entry;
    return next();
  });
  publicApp.post(authorizationPath, express.urlencoded({ limit: '256kb', extended: false, parameterLimit: 1, inflate: false }), (req, res, next) => {
    const entry = req.walletEntry;
    if (!entry || entry.expiresAt <= Date.now()) return fixedError(res, 404);
    if (entry.finished || entry.processing) return fixedError(res, 409);
    // Credo marks a session terminal when it cannot parse its JARM response.
    if (!keys(req.body, ['response']) || !acceptsEncryptedResponse(req.body.response, entry)) {
      return fixedError(res, 400);
    }
    entry.processing = true;
    res.once('finish', () => {
      entry.processing = false;
      entry.finished = true;
      entry.responseStatus = res.statusCode;
    });
    res.once('close', () => {
      if (!res.writableFinished) entry.outage = true;
    });
    return context.run(entry, next);
  });

  const agent = new Agent({
    config: {
      logger: new ConsoleLogger(LogLevel.Off),
      getTrustedIssuersForVerification: async (_context, { signer, verification }) => {
        const entry = verification.type === 'openId4VpCredential'
          && byId.get(verification.openId4VcVerificationSessionRecord.id);
        if (signer.method !== 'x509' || !entry || entry.expiresAt <= Date.now()
          || entry.walletNonce !== verification.openId4VcVerificationSessionRecord.requestPayload.nonce) {
          return { trustedIssuers: [] };
        }
        return { trustedIssuers: [{ method: 'x509', issuance: entry.issuerCertificates }] };
      },
    },
    dependencies: {
      ...agentDependencies,
      fetch: async () => {
        const entry = context.getStore();
        if (entry) entry.outage = true;
        throw new Error('Outbound resource resolution is disabled for this verifier');
      },
    },
    modules: {
      askar: new AskarModule({
        askar: NativeAskar,
        enableKms: false,
        store,
      }),
      kms: new KeyManagementModule({
        backends: [new NodeKeyManagementService(new NodeInMemoryKeyManagementStorage())],
      }),
      openid4vc: new OpenId4VcModule({ app: publicApp, verifier: { baseUrl: config.publicOrigin + walletBase } }),
    },
  });
  await agent.initialize();
  const verifier = agent.openid4vc.verifier;
  await verifier.createVerifier({ verifierId, clientMetadata: { client_name: 'ProofSieve' } });
  const signingKey = await agent.kms.importKey({ privateJwk: config.verifierJwk });
  const x5c = config.verifierCertificates.map((certificate) => X509Certificate.fromEncodedCertificate(certificate));
  x5c[0].keyId = signingKey.keyId;

  privateApp.use((req, res, next) => {
    const actual = Buffer.from(req.headers.authorization ?? '');
    if (actual.length !== config.bearer.length || !timingSafeEqual(actual, config.bearer)) return fixedError(res, 401);
    next();
  });
  privateApp.post(internalBase, express.json({ limit: '64kb', inflate: false }), async (req, res) => {
    let credential;
    let issuerCertificates;
    const body = req.body;
    try {
      assert(keys(body, ['dcql_query', 'nonce', 'issuer_chain', 'intended_use_id']) && typeof body.nonce === 'string'
        && noncePattern.test(body.nonce) && body.intended_use_id === config.intendedUseId, 'Invalid transaction settings');
      credential = queryCredential(body.dcql_query);
      issuerCertificates = certificates(body.issuer_chain);
    } catch {
      return fixedError(res, 400);
    }
    if (byId.size + inProgress.size >= maxSessions || inProgress.has(body.nonce)
      || [...byId.values()].some((entry) => entry.nonce === body.nonce)) return fixedError(res, 503);
    inProgress.add(body.nonce);
    try {
      const { verificationSession: session } = await verifier.createAuthorizationRequest({
        verifierId,
        requestSigner: { method: 'x5c', x5c, clientIdPrefix: 'x509_hash' },
        dcql: { query: body.dcql_query },
        responseMode: 'direct_post.jwt',
        version: 'v1',
        expirationInSeconds: ttlSeconds,
      });
      const request = session.requestPayload;
      const encryptionKey = request.client_metadata?.jwks?.keys.find((key) => key.use === 'enc');
      const keyId = encryptionKey?.kid;
      const responseEncryption = (request.client_metadata?.encrypted_response_enc_values_supported ?? ['A128GCM'])
        .filter(algorithm => gcmAlgorithms.includes(algorithm));
      if (!uuid.test(session.id) || !uuid.test(session.authorizationRequestId) || request.client_id !== config.clientId
        || !noncePattern.test(request.nonce) || session.authorizationRequestUri !== config.publicOrigin + requestPrefix + session.authorizationRequestId
        || request.response_uri !== config.publicOrigin + authorizationPath + '?session=' + session.authorizationRequestId
        || request.response_mode !== 'direct_post.jwt' || session.openId4VpVersion !== 'v1' || !(session.expiresAt instanceof Date)
        || !keyId || encryptionKey.kty !== 'EC' || !encryptionKey.x || !responseEncryption.length) {
        await verifier.deleteVerificationSessionById(session.id);
        if (keyId) await agent.kms.deleteKey({ keyId });
        return fixedError(res, 503);
      }
      const entry = {
        id: session.id, requestId: session.authorizationRequestId, nonce: body.nonce, walletNonce: request.nonce,
        keyId, responseEncryption, encryptionCurve: encryptionKey.crv, coordinateLength: encryptionKey.x.length,
        format: credential.format, issuerCertificates, expiresAt: session.expiresAt.getTime(),
        credentialType: credential.format === statusFormat ? credential.meta.vct_values[0] : credential.meta.doctype_value,
      };
      byId.set(entry.id, entry);
      byRequest.set(entry.requestId, entry);
      return res.json({
        transaction_id: entry.id, nonce: entry.nonce, client_id: config.clientId,
        request_uri: session.authorizationRequestUri,
      });
    } finally {
      inProgress.delete(body.nonce);
    }
  });
  privateApp.get(internalBase + '/:id', async (req, res) => {
    const entry = uuid.test(req.params.id) && byId.get(req.params.id);
    if (!entry || entry.expiresAt <= Date.now() || req.originalUrl !== internalBase + '/' + req.params.id) return fixedError(res, 404);
    if (entry.outage) return fixedError(res, 503);
    const binding = { transaction_id: entry.id, nonce: entry.nonce, client_id: config.clientId };
    if (!entry.finished) return res.json({ ...binding, state: 'pending' });
    const session = await verifier.getVerificationSessionById(entry.id);
    const request = session.requestPayload;
    assert(session.id === entry.id && session.authorizationRequestId === entry.requestId && session.verifierId === verifierId
      && request.nonce === entry.walletNonce && request.client_id === config.clientId && session.openId4VpVersion === 'v1',
    'Credo result binding did not match');
    if (session.state === 'Error' && entry.responseStatus >= 400 && entry.responseStatus < 500) {
      return res.json({ ...binding, state: 'rejected' });
    }
    if (session.state !== 'ResponseVerified' || entry.responseStatus < 200 || entry.responseStatus >= 300) return fixedError(res, 503);
    const result = await verifier.getVerifiedAuthorizationResponse(entry.id);
    const presentations = result.dcql?.presentations;
    assert(keys(presentations, ['credential']) && Array.isArray(presentations.credential) && presentations.credential.length === 1,
      'Unexpected Credo result cardinality');
    const [credential] = presentations.credential;
    const raw = result.verificationSession.authorizationResponsePayload?.vp_token?.credential;
    assert(Array.isArray(raw) && raw.length === 1 && typeof raw[0] === 'string' && raw[0].length <= maxPresentation
      && credential.claimFormat === entry.format, 'Unexpected Credo presentation result');
    let verified;
    if (entry.format === statusFormat) {
      verified = credential.prettyClaims;
      assert(verified?.vct === entry.credentialType, 'Unexpected SD-JWT credential type');
    } else {
      assert(credential.deviceResponse.documents?.length === 1
        && keys(credential.issuerClaims, [entry.credentialType]), 'Exactly one expected mdoc required');
      verified = [{ docType: entry.credentialType, attributes: credential.issuerClaims[entry.credentialType] }];
    }
    const payload = JSON.stringify({ ...binding, state: 'verified', format: entry.format, presentation: raw[0], verified },
      (_key, value) => {
        assert(typeof value !== 'number' || Number.isFinite(value) && (!Number.isInteger(value) || Number.isSafeInteger(value)),
          'Unrepresentable verified numeric claim');
        return value;
      });
    assert(Buffer.byteLength(payload) <= maxBridgeResponse, 'Credo response exceeds the configured limit');
    return res.type('application/json').send(payload);
  });

  for (const app of [publicApp, privateApp]) {
    app.use((_req, res) => fixedError(res, 404));
    app.use((error, _req, res, _next) => {
      if (!res.headersSent) fixedError(res, error.status === 400 || error.status === 413 ? error.status : 503);
    });
  }
  const timer = setInterval(async () => {
    for (const entry of byId.values()) {
      if (entry.expiresAt > Date.now()) continue;
      byId.delete(entry.id);
      byRequest.delete(entry.requestId);
      try {
        await verifier.deleteVerificationSessionById(entry.id);
        if (entry.keyId) await agent.kms.deleteKey({ keyId: entry.keyId });
      } catch {
        // Stop the ephemeral process instead of retaining unbounded presentation data.
        process.exit(1);
      }
    }
  }, 1000);
  timer.unref();
  const publicServer = await bindServer(publicApp, config.tls, config.publicHost, config.publicPort);
  const privateServer = await bindServer(privateApp, config.tls, '127.0.0.1', config.privatePort);
  for (const signal of ['SIGTERM', 'SIGINT']) {
    process.once(signal, async () => {
      clearInterval(timer);
      publicServer.close();
      privateServer.close();
      await agent.shutdown();
      process.exit(0);
    });
  }
  console.log('Credo wallet bridge ready');
}

try {
  assert(process.argv.length === 3, 'Usage: node server.mjs /absolute/config.json');
  const config = readConfig(process.argv[2]);
  const store = createTransientStore(verifierId);
  process.once('exit', store.dispose);
  await start(config, store.config);
} catch (error) {
  console.error('Credo wallet bridge could not start:', error.message);
  process.exit(1);
}
