const {GoogleAuth} = require('google-auth-library');
const mode = process.argv[2] || 'default';
const n = +(process.env.N || 2), sleep = +(process.env.SLEEP || 0);
(async () => {
  const opts = {scopes: ['https://www.googleapis.com/auth/cloud-platform']};
  if (mode === 'noscope') delete opts.scopes;
  const auth = new GoogleAuth(opts);
  const client = await auth.getClient();
  console.log('client:', client.constructor.name);
  for (let i = 0; i < n; i++) {
    const r = await client.request({url: 'https://storage.googleapis.com/storage/v1/b?project=spike-proj'});
    console.log('api', r.status, 'token:', client.credentials && client.credentials.access_token, 'expiry:', client.credentials && client.credentials.expiry_date);
    await new Promise(r => setTimeout(r, sleep * 1000));
  }
})().catch(e => { console.log('ERR', e.message); process.exit(1); });
