const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
};

async function generateKeys() {
	const keyPair = await crypto.subtle.generateKey(
		{
			name: "RSA-OAEP",
			modulusLength: 2048,
			publicExponent: new Uint8Array([1, 0, 1]),
			hash: "SHA-256",
		},
		true,
		["encrypt", "decrypt"]
	);

	const publicKey = await crypto.subtle.exportKey("spki", keyPair.publicKey);
	const privateKey = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

	return {
		publicKey: arrayBufferToBase64(publicKey),
		privateKey: arrayBufferToBase64(privateKey),
	};
}

// use these in your worker env vars
(async () => {
	const keys = await generateKeys();
	console.log("PUBLIC_KEY:", keys.publicKey);
	console.log("PRIVATE_KEY:", keys.privateKey);
})();
