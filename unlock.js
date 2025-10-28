const enc = new TextEncoder();
const dec = new TextDecoder();

function b64decode(str){
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

async function deriveKey(password, salt){
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name:"PBKDF2" }, false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:250000, hash:"SHA-256" },
    keyMaterial,
    { name:"AES-GCM", length:256 },
    false,
    ["decrypt"]
  );
}

async function unlockWith(password){
  const res = await fetch('encrypted-content.json', {cache:'no-store'});
  if(!res.ok) throw new Error("Cannot load encrypted content.");
  const payload = await res.json();

  const salt = new Uint8Array(new Uint8Array(b64decode(payload.salt)));
  const iv   = new Uint8Array(new Uint8Array(b64decode(payload.iv)));
  const data = new Uint8Array(new Uint8Array(b64decode(payload.data)));

  const key = await deriveKey(password, salt);
  const plaintext = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, data);
  return dec.decode(plaintext);
}

document.getElementById('unlock').addEventListener('click', async () => {
  const pw = document.getElementById('pw').value;
  const error = document.getElementById('error');
  error.style.display = 'none';
  try{
    const html = await unlockWith(pw);
    const iframe = document.getElementById('viewer');
    const blob = new Blob([html], {type:"text/html"});
    iframe.src = URL.createObjectURL(blob);
    document.getElementById('content').style.display = 'block';
    document.getElementById('gate').style.display = 'none';
  }catch(e){
    error.style.display = 'block';
  }
});

