const { spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

function ffmpegAvailable() {
  const check = spawnSync('ffmpeg', ['-version']);
  return check.status === 0;
}

// Extracts `count` evenly-spaced JPEG frames from a video buffer using ffmpeg.
// Returns an array of { base64, mimeType } objects. Requires ffmpeg to be
// installed on the host running the Node backend; if it isn't, returns an
// empty array so callers can degrade gracefully (still run Gemini directly
// on the raw video where the API/plan supports it, or report the limitation).
function extractFrames(videoBuffer, count = 4) {
  if (!ffmpegAvailable()) return { frames: [], ffmpegAvailable: false };

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-video-'));
  const videoPath = path.join(tmpDir, 'input.mp4');
  fs.writeFileSync(videoPath, videoBuffer);

  try {
    // Probe duration first so frames are evenly spaced across the whole clip.
    const probe = spawnSync('ffprobe', [
      '-v', 'error', '-show_entries', 'format=duration',
      '-of', 'default=noprint_wrappers=1:nokey=1', videoPath,
    ]);
    const duration = parseFloat(probe.stdout?.toString().trim()) || 5;

    const frames = [];
    for (let i = 0; i < count; i++) {
      const t = Math.max(0.1, (duration * (i + 1)) / (count + 1));
      const framePath = path.join(tmpDir, `frame_${i}.jpg`);
      spawnSync('ffmpeg', ['-y', '-ss', String(t), '-i', videoPath, '-frames:v', '1', '-q:v', '3', framePath]);
      if (fs.existsSync(framePath)) {
        frames.push({ base64: fs.readFileSync(framePath).toString('base64'), mimeType: 'image/jpeg' });
      }
    }
    return { frames, ffmpegAvailable: true, durationSeconds: duration };
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// Converts any audio (mp3/m4a/ogg/webm/wav...) to 16 kHz mono 16-bit WAV so
// the C++ signal forensics and the audio ML model can analyse it.
function toWav16k(buffer, ext = 'bin') {
  if (!ffmpegAvailable()) return null;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cg-audio-'));
  const inPath = path.join(tmpDir, `input.${ext.replace(/[^a-z0-9]/gi, '') || 'bin'}`);
  const outPath = path.join(tmpDir, 'out.wav');
  fs.writeFileSync(inPath, buffer);
  try {
    spawnSync('ffmpeg', ['-y', '-i', inPath, '-vn', '-ac', '1', '-ar', '16000', '-t', '120', '-acodec', 'pcm_s16le', outPath]);
    return fs.existsSync(outPath) ? fs.readFileSync(outPath) : null;
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// Voice track of a video (for voice-clone detection on video calls / clips).
function extractAudioWav(videoBuffer) {
  return toWav16k(videoBuffer, 'mp4');
}

module.exports = { extractFrames, ffmpegAvailable, toWav16k, extractAudioWav };
