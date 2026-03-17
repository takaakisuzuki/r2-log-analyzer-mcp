import { CipherSuite, HkdfSha256 } from "@hpke/core";
import { DhkemX25519HkdfSha256 } from "@hpke/dhkem-x25519";
import { Chacha20Poly1305 } from "@hpke/chacha20poly1305";

const suite = new CipherSuite({
	kem: new DhkemX25519HkdfSha256(),
	kdf: new HkdfSha256(),
	aead: new Chacha20Poly1305(),
});

function b64decode(base64: string): ArrayBuffer {
	const binaryString = atob(base64);
	const length = binaryString.length;
	const bytes = new Uint8Array(length);
	for (let i = 0; i < length; i++) {
		bytes[i] = binaryString.charCodeAt(i);
	}
	return bytes.buffer;
}

function decodebin(enc: ArrayBuffer) {
	const version = new TextDecoder().decode(enc.slice(0, 1)).charCodeAt(0);
	switch (version) {
		case 3:
			return {
				version,
				encappedKey: enc.slice(1, 33),
				payloadLength: new DataView(enc.slice(33, 41)).getUint8(0),
				payload: enc.slice(41),
			};
		default:
			return {
				version,
				encappedKey: new TextEncoder().encode(""),
				payloadLength: 0,
				payload: new TextEncoder().encode(""),
			};
	}
}

/**
 * Decrypt a single encrypted_matched_data payload using the private key.
 */
export async function decryptMatchedData(
	payloadBase64: string,
	privateKeyBase64: string,
): Promise<string | undefined> {
	try {
		const encData = decodebin(b64decode(payloadBase64));

		const recipient = await suite.createRecipientContext({
			recipientKey: await suite.kem.importKey(
				"raw",
				b64decode(privateKeyBase64),
			),
			enc: encData.encappedKey,
		});

		const pt = await recipient.open(encData.payload);
		return new TextDecoder().decode(pt);
	} catch (err) {
		console.warn("Failed to decrypt matched data:", err);
		return undefined;
	}
}

/**
 * Process a log entry: if it has Metadata.encrypted_matched_data and a
 * private key is available, decrypt and attach as decrypted_matched_data.
 */
export async function decryptLogEntry(
	entry: Record<string, any>,
	privateKey: string | undefined,
): Promise<Record<string, any>> {
	if (
		!privateKey ||
		!entry.Metadata ||
		!entry.Metadata.encrypted_matched_data
	) {
		return entry;
	}

	const decrypted = await decryptMatchedData(
		entry.Metadata.encrypted_matched_data,
		privateKey,
	);

	if (decrypted) {
		let parsed: any;
		try {
			parsed = JSON.parse(decrypted);
		} catch {
			parsed = decrypted;
		}
		return {
			...entry,
			Metadata: {
				...entry.Metadata,
				decrypted_matched_data: parsed,
			},
		};
	}

	return entry;
}

/**
 * Batch-decrypt log entries that contain encrypted matched data.
 */
export async function decryptLogEntries(
	entries: Record<string, any>[],
	privateKey: string | undefined,
): Promise<Record<string, any>[]> {
	if (!privateKey) return entries;

	return Promise.all(entries.map((e) => decryptLogEntry(e, privateKey)));
}
