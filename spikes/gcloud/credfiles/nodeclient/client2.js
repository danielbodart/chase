const {GoogleAuth} = require('google-auth-library');
const https = require('https');
const mode = process.argv[2];
(async () => {
  const opts = mode === 'jwtaccess-scope' ? {scopes: ['https://www.googleapis.com/auth/cloud-platform'], clientOptions: {useJWTAccessWithScope: true}} : {};
  const auth = new GoogleAuth(opts);
  const client = await auth.getClient();
  if (mode === 'jwtaccess-scope') client.useJWTAccessWithScope = true;
  const url = 'https://storage.googleapis.com/storage/v1/b?project=spike-proj';
  const h = await client.getRequestHeaders(url);
  const auth_ = h.get ? h.get('authorization') : h.Authorization;
  console.log('header:', (auth_||'').slice(0, 40));
  await new Promise((res, rej) => https.get(url, {headers: {authorization: auth_}}, r => { console.log('api', r.statusCode); r.resume(); r.on('end', res); }).on('error', rej));
})().catch(e => { console.log('ERR', e.message); process.exit(1); });
