
document.getElementById('file-button').addEventListener('click', function() {
  document.getElementById('input-file').click();
});
document.getElementById('input-file').addEventListener('change', function(event) {
  const fileName = event.target.files[0]?.name || 'No file chosen';
  document.getElementById('file-name-display').textContent = `File selected: ${fileName}`;
});



function sha256(text) {
  
  
  const K = [
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  const ROTR = (n, x) => (x >>> n) | (x << (32 - n));
  const Σ0 = x => ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x);
  const Σ1 = x => ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x);
  const σ0 = x => ROTR(7, x) ^ ROTR(18, x) ^ (x >>> 3);
  const σ1 = x => ROTR(17, x) ^ ROTR(19, x) ^ (x >>> 10);

  function toHexStr(n) {
      return ('00000000' + n.toString(16)).slice(-8);
  }

  const H = [
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];
  
  const utf8Encode = str => unescape(encodeURIComponent(str));
  const bytes = Array.from(utf8Encode(text)).map(c => c.charCodeAt(0));

  bytes.push(0x80);

  while ((bytes.length % 64) !== 56) bytes.push(0x00);

  const bitLen = text.length * 8;
  bytes.push(0, 0, 0, 0);
  bytes.push((bitLen >>> 24) & 0xff);
  bytes.push((bitLen >>> 16) & 0xff);
  bytes.push((bitLen >>> 8) & 0xff);
  bytes.push(bitLen & 0xff);

  for (let i = 0; i < bytes.length; i += 64) {
      const chunk = bytes.slice(i, i + 64);
      const W = new Array(64);
      for (let j = 0; j < 16; j++) {
          W[j] = (chunk[j * 4] << 24) | (chunk[j * 4 + 1] << 16) | (chunk[j * 4 + 2] << 8) | (chunk[j * 4 + 3]);
      }
      for (let j = 16; j < 64; j++) {
          W[j] = (σ1(W[j - 2]) + W[j - 7] + σ0(W[j - 15]) + W[j - 16]) >>> 0;
      }

      let [a, b, c, d, e, f, g, h] = H;

      for (let j = 0; j < 64; j++) {
          const T1 = (h + Σ1(e) + ((e & f) ^ (~e & g)) + K[j] + W[j]) >>> 0;
          const T2 = (Σ0(a) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
          h = g;
          g = f;
          f = e;
          e = (d + T1) >>> 0;
          d = c;
          c = b;
          b = a;
          a = (T1 + T2) >>> 0;
      }

      H[0] = (H[0] + a) >>> 0;
      H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0;
      H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0;
      H[7] = (H[7] + h) >>> 0;
  }

  return H.map(toHexStr).join('');
}


document.getElementById("hash-button-text").addEventListener("click", () => {
  const text = document.getElementById("input-text").value;
  if (text) {
      const hashHex = sha256(text);
      document.getElementById("output-text").value = hashHex;
      document.getElementById("file-name-display").innerText = " ";
  } else {
      alert("Please enter text to hash.");
  }
});

document.getElementById("hash-button-file").addEventListener("click", async () => {
  const fileInput = document.getElementById("input-file");
  const file = fileInput.files[0];

  if (file && file.size <= 10 * 1024 * 1024) { 
      const reader = new FileReader();
      reader.onload = async function (e) {
          const fileContent = new Uint8Array(e.target.result); 
          const hashHex = sha256(fileContent);
          document.getElementById("output-text").value = hashHex;
      };
      reader.readAsArrayBuffer(file);
      document.getElementById("input-text").value = "";
  } else if (!file) {
      alert("Please select a file.");
  } else {
      alert("File size exceeds 10MB. Please choose a smaller file.");
  }
});


document.getElementById("clear-button").addEventListener("click",() => {
  document.getElementById("output-text").value = "";
  document.getElementById("input-text").value = "";
  document.getElementById("file-name-display").innerText = "";
})
