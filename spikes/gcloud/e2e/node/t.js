const {Storage} = require('@google-cloud/storage');
(async () => {
  const [buf] = await new Storage().bucket('danbodart-sandbox-test-frisket-spike').file('hello.txt').download();
  console.log('node download:', JSON.stringify(buf.toString()));
})().catch(e => { console.error('node FAIL', e.message); process.exit(1); });
