const axios = require('axios');

const ENGINE_URL = process.env.ENGINE_URL || 'http://127.0.0.1:5050';
const ENGINE_KEY = process.env.ENGINE_KEY || '';

const client = axios.create({
  baseURL: ENGINE_URL,
  timeout: 15000,
  headers: ENGINE_KEY ? { 'x-engine-key': ENGINE_KEY } : {},
  maxBodyLength: 300 * 1024 * 1024,
  maxContentLength: 300 * 1024 * 1024,
});

async function analyzeUrl(url) {
  const { data } = await client.post('/analyze/url', { url });
  return data;
}

async function analyzeText(text, claimedSender = '') {
  const { data } = await client.post('/analyze/text', { text, claimedSender });
  return data;
}

async function analyzeLogin(payload) {
  const { data } = await client.post('/analyze/login', payload);
  return data;
}

async function analyzeImage(imageBase64) {
  const { data } = await client.post('/analyze/image', { imageBase64 }, { timeout: 60000 });
  return data;
}

async function analyzeAudio(audioBase64) {
  const { data } = await client.post('/analyze/audio', { audioBase64 }, { timeout: 60000 });
  return data;
}

async function analyzeLogs(entries) {
  const { data } = await client.post('/analyze/logs', { entries }, { timeout: 30000 });
  return data;
}

// Network IDS: raw capture bytes (pcap / pcapng)
async function analyzePcap(buffer, name) {
  const { data } = await client.post(`/analyze/pcap?name=${encodeURIComponent(name || 'upload.pcap')}`, buffer, {
    headers: { 'Content-Type': 'application/octet-stream' },
    timeout: 180000,
  });
  return data;
}

async function nidsInterfaces() {
  const { data } = await client.get('/nids/interfaces');
  return data;
}
async function nidsLiveStart(opts) {
  const { data } = await client.post('/nids/live/start', opts || {});
  return data;
}
async function nidsLiveStop() {
  const { data } = await client.post('/nids/live/stop', {});
  return data;
}
async function nidsLiveStatus() {
  const { data } = await client.get('/nids/live/status');
  return data;
}

async function modelCards() {
  const { data } = await client.get('/ml/models');
  return data;
}
async function retrainLogin(events) {
  const { data } = await client.post('/ml/train/login', { events }, { timeout: 120000 });
  return data;
}

async function fuse(components, findings) {
  const { data } = await client.post('/fuse', { components, findings });
  return data;
}

async function healthCheck() {
  const { data } = await client.get('/health');
  return data;
}

module.exports = {
  analyzeUrl, analyzeText, analyzeLogin, analyzeImage, analyzeAudio, analyzeLogs, analyzePcap,
  nidsInterfaces, nidsLiveStart, nidsLiveStop, nidsLiveStatus, modelCards, retrainLogin, fuse, healthCheck,
};
