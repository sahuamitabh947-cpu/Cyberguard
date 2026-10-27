#!/usr/bin/env bash
# Downloads the public datasets used by cg_train into this folder.
# You only need this to RE-TRAIN: trained models already ship in
# detection-engine-cpp/models/.
#
#   cd datasets && bash fetch_datasets.sh
#   ../detection-engine-cpp/build/cg_train . ../detection-engine-cpp/models all
#
# Requires: curl, unzip, (optional) shuf, espeak-ng, ffmpeg
set -euo pipefail
cd "$(dirname "$0")"
get() { echo "-> $2"; curl -fL --retry 3 -o "$2" "$1"; }

# Phishing text: UCI SMS Spam Collection (CC BY 4.0) + Enron-Spam
get https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip sms.zip
unzip -o -q sms.zip SMSSpamCollection && mv SMSSpamCollection sms.tsv && rm sms.zip
get https://raw.githubusercontent.com/MWiechmann/enron_spam_data/master/enron_spam_data.zip enron.zip
unzip -o -q enron.zip && rm enron.zip

# URLs: faizann24 malicious/benign URL list + a sample of Phishing.Database ACTIVE (MIT)
get https://raw.githubusercontent.com/faizann24/Using-machine-learning-to-detect-malicious-URLs/master/data/data.csv urls_faizann.csv
get https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt phishing_active.txt
if command -v shuf >/dev/null; then shuf -n 60000 --random-source=<(yes) phishing_active.txt > urls_phishing_recent.txt
else head -n 60000 phishing_active.txt > urls_phishing_recent.txt; fi
rm phishing_active.txt

# Network IDS: NSL-KDD (University of New Brunswick, CIC)
get https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt KDDTrain.txt
get https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt KDDTest.txt

# Public Suffix List (registrable-domain logic)
get https://publicsuffix.org/list/public_suffix_list.dat psl.dat

# Images: put your own ORIGINAL (unedited) photos here; the trainer creates the
# manipulated versions itself (splicing, copy-move, retouching, resampling...).
mkdir -p images/originals
# Audio: real speech WAVs in audio/real (e.g. LibriSpeech / Mozilla Common Voice
# clips converted with: ffmpeg -i in.flac -ac 1 -ar 16000 out.wav) and synthetic
# speech in audio/tts. The trainer also makes Griffin-Lim vocoded fakes from the real clips.
mkdir -p audio/real audio/tts
if command -v espeak-ng >/dev/null; then
  i=0
  for v in en-us en-gb en-in en-au en+f3 en+m3; do
    for s in "Hello, this is your bank calling about suspicious activity on your account." \
             "Please share the one time password you just received to verify your identity." \
             "I am the director, I need you to transfer the funds before end of day." \
             "Your parcel is on hold, confirm your address and pay the small customs fee." \
             "We noticed a login from a new device, press one to secure your account." \
             "This is technical support, please install the remote access tool now." \
             "Hi mum, I lost my phone, can you send money to this new number." \
             "The meeting has moved, please review the attached invoice today." \
             "Congratulations, you have won a cash prize, claim it within an hour." \
             "Your electricity will be disconnected tonight unless you pay immediately." \
             "Kindly update your KYC details to avoid your account being blocked." \
             "I will call you back later, the network here is very weak."; do
      espeak-ng -v "$v" -s $((140 + RANDOM % 40)) -w "audio/tts/tts_$i.wav" "$s"; i=$((i+1))
    done
  done
  echo "generated $i TTS clips"
else
  echo "espeak-ng not found - add synthetic speech WAVs to audio/tts yourself"
fi
echo "Done. Add real speech to audio/real and photos to images/originals before training audio/image models."
