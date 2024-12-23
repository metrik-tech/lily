const base64ToArrayBuffer = (base64: string): ArrayBuffer => {
	const binary = atob(base64.replace(/-/g, "+").replace(/_/g, "/"));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes.buffer;
};

const arrayBufferToBase64 = (buffer: ArrayBuffer): string => {
	const bytes = new Uint8Array(buffer);
	let binary = "";
	for (let i = 0; i < bytes.byteLength; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_");
};

export class LilyCrypto {
	private privateKey: CryptoKey | null = null;
	private publicKey: CryptoKey | null = null;

	constructor(private privateKeyB64: string, private publicKeyB64: string) {}

	async init() {
		const privateKeyData = base64ToArrayBuffer(this.privateKeyB64);
		this.privateKey = await crypto.subtle.importKey(
			"pkcs8",
			privateKeyData,
			{
				name: "RSA-OAEP",
				hash: "SHA-256",
			},
			true,
			["decrypt"]
		);

		const publicKeyData = base64ToArrayBuffer(this.publicKeyB64);
		this.publicKey = await crypto.subtle.importKey(
			"spki",
			publicKeyData,
			{
				name: "RSA-OAEP",
				hash: "SHA-256",
			},
			true,
			["encrypt"]
		);
	}

	async decrypt(encryptedData: string): Promise<string> {
		if (!this.privateKey) throw new Error("Crypto not initialized");

		const encryptedBytes = base64ToArrayBuffer(encryptedData);
		const decrypted = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, this.privateKey, encryptedBytes);

		return new TextDecoder().decode(decrypted);
	}

	getPublicKey(): string {
		return this.publicKeyB64;
	}
}
