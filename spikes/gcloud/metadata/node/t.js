const {GoogleAuth} = require('google-auth-library');
(async () => {
  const t0 = Date.now();
  const auth = new GoogleAuth({scopes: ['https://www.googleapis.com/auth/cloud-platform']});
  try {
    const client = await auth.getClient();
    console.log('getClient:', client.constructor.name, (Date.now() - t0) + 'ms');
    console.log('projectId:', await auth.getProjectId().catch(e => 'ERR ' + e.message));
    const n = +(process.env.LOOPS || 1);
    for (let i = 0; i < n; i++) {
      const r = await client.request({url: 'https://storage.googleapis.com/storage/v1/b?project=frisket-spike'});
      console.log(i, r.status, JSON.stringify(r.data).slice(0, 60), 'expiry', client.credentials.expiry_date);
      await new Promise(r => setTimeout(r, +(process.env.SLEEP || 1) * 1000));
    }
    if (process.env.IDTOK) {
      const idc = await auth.getIdTokenClient('https://example.run.app');
      const h = await idc.getRequestHeaders(); console.log('idtoken authorization:', String(h.get ? h.get('authorization') : h.Authorization).slice(0, 60));
    }
  } catch (e) { console.log('ERROR', (Date.now() - t0) + 'ms', e.message.slice(0, 300)); }
})();
