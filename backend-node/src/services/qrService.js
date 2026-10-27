const { Jimp } = require('jimp');
const jsQR = require('jsqr');

// Attempts to decode a QR code from an uploaded image buffer.
// Returns the decoded string (typically a URL) or null if no QR code found.
// This directly serves the PRD's "QR-code-based phishing" requirement:
// once decoded, the payload is run through the same url_analyzer / text_analyzer
// pipeline as any other submitted URL/message.
async function decodeQrFromBuffer(buffer) {
  try {
    const image = await Jimp.read(buffer);
    const { data, width, height } = image.bitmap;
    const result = jsQR(new Uint8ClampedArray(data.buffer, data.byteOffset, data.length), width, height);
    return result ? result.data : null;
  } catch (e) {
    return null;
  }
}

module.exports = { decodeQrFromBuffer };
