const {Storage} = require('@google-cloud/storage');
const {PubSub} = require('@google-cloud/pubsub');
const {GoogleAuth} = require('google-auth-library');
const T = 'frisket-spike';
const step = async (n, f) => { try { console.log(n + ':', await f()); } catch (e) { console.log(n, 'FAIL', (e.message || String(e)).slice(0, 200)); } };
(async () => {
  const s = new Storage();
  await step('node storage download', async () => JSON.stringify((await s.bucket('danbodart-sandbox-test-frisket-spike').file('hello.txt').download())[0].toString()));
  for (const fallback of [false, 'rest']) {
    const ps = new PubSub(fallback ? {fallback} : {});
    for (let i = 0; i < 2; i++)
      await step(`node pubsub ${fallback || 'grpc'} getMetadata`, async () => (await ps.topic(T).getMetadata())[0].name);
    await ps.close();
  }
  const auth = new GoogleAuth();
  await step('node idtoken', async () => {
    const c = await auth.getIdTokenClient('https://example-run-service.a.run.app');
    const h = await c.getRequestHeaders();
    const tok = (h.get ? h.get('authorization') : h.Authorization).split(' ')[1];
    const cl = JSON.parse(Buffer.from(tok.split('.')[1], 'base64url'));
    return `iss ${cl.iss} aud ${cl.aud}`;
  });
  await step('node signed url', async () => {
    const [u] = await s.bucket('danbodart-sandbox-test-frisket-spike').file('hello.txt').getSignedUrl({action: 'read', expires: Date.now() + 300000, version: 'v4'});
    const r = await fetch(u);
    return `${u.split('?')[0]} -> ${r.status} ${(await r.text()).slice(0, 80)}`;
  });
})();
