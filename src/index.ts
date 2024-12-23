import { LilyCrypto } from "./lib/crypto";
import { GraphDatabase } from "./lib/graph";
import { UserTracker } from "./lib/tracking";

class APIError extends Error {
	constructor(public status: number, message: string) {
		super(message);
		this.name = "APIError";
	}
}

const jsonResponse = (data: any, status = 200) =>
	new Response(JSON.stringify(data), {
		status,
		headers: {
			"Content-Type": "application/json",
			"Access-Control-Allow-Origin": "*",
			"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
			"Access-Control-Allow-Headers": "Content-Type, Authorization",
		},
	});

const errorResponse = (error: Error) => {
	console.error("Error:", error);
	if (error instanceof APIError) {
		return jsonResponse({ error: error.message }, error.status);
	}
	return jsonResponse({ error: "Internal Server Error" }, 500);
};

const authenticate = (request: Request, apiKey: string): void => {
	const authHeader = request.headers.get("Authorization");
	if (!authHeader) {
		throw new APIError(401, "Missing Authorization header");
	}

	const [type, token] = authHeader.split(" ");
	if (type !== "Bearer" || token !== apiKey) {
		throw new APIError(401, "Invalid API key");
	}
};

export default {
	async fetch(request: Request, env: Env): Promise<Response> {
		if (request.method === "OPTIONS") {
			return new Response(null, {
				headers: {
					"Access-Control-Allow-Origin": "*",
					"Access-Control-Allow-Methods": "GET, POST, OPTIONS",
					"Access-Control-Allow-Headers": "Content-Type, Authorization",
				},
			});
		}

		try {
			const url = new URL(request.url);
			if (url.pathname !== "/health" && url.pathname !== "/keys") {
				authenticate(request, env.API_KEY);
			}

			const crypto = new LilyCrypto(env.PRIVATE_KEY, env.PUBLIC_KEY);
			await crypto.init();

			const db = new GraphDatabase(env.LILY_DB);
			const tracker = new UserTracker(env.LILY_DB);

			switch (url.pathname) {
				case "/health":
					return jsonResponse({ status: "ok" });

				case "/keys": {
					return jsonResponse({
						publicKey: crypto.getPublicKey(),
						algorithm: "RSA-OAEP",
						hash: "SHA-256",
					});
				}

				case "/track": {
					if (request.method !== "POST") {
						throw new APIError(405, "Method not allowed");
					}

					const encryptedData = await request.json<{ payload: string }>();
					if (!encryptedData.payload) {
						throw new APIError(400, "Missing payload");
					}

					const decryptedJson = await crypto.decrypt(encryptedData.payload);
					const data = JSON.parse(decryptedJson) as { userId: string; ip: string; fingerprint: string };

					if (!data.userId || !data.ip || !data.fingerprint) {
						throw new APIError(400, "Missing required fields");
					}

					await tracker.recordConnection(data.userId, data.ip, data.fingerprint, request.headers.get("User-Agent") || "");

					return jsonResponse({ status: "recorded" });
				}

				case "/graph": {
					if (request.method !== "GET") {
						throw new APIError(405, "Method not allowed");
					}

					const hours = parseInt(url.searchParams.get("hours") || "24");
					const minRisk = parseInt(url.searchParams.get("minRisk") || "0");

					const graphData = await tracker.getConnectionGraph({
						hours,
						riskThreshold: minRisk,
					});

					return jsonResponse(graphData);
				}

				case "/user-connections": {
					if (request.method !== "GET") {
						throw new APIError(405, "Method not allowed");
					}

					const userId = url.searchParams.get("userId");
					if (!userId) {
						throw new APIError(400, "Missing userId parameter");
					}

					const connections = await tracker.getUserConnections(userId);
					return jsonResponse(connections);
				}

				case "/stats": {
					if (request.method !== "GET") {
						throw new APIError(405, "Method not allowed");
					}

					const stats = {
						users: (await db.query({ type: "USER" })).items.length,
						activeUsers: 0,
						uniqueIPs: 0,
						uniqueFingerprints: 0,
						timestamp: new Date().toISOString(),
					};

					const graph = await tracker.getConnectionGraph({ hours: 24 });
					const activeNodes = new Set(graph.nodes.map((n) => n.id));

					stats.activeUsers = graph.nodes.filter((n) => n.type === "USER").length;
					stats.uniqueIPs = graph.nodes.filter((n) => n.type === "IP").length;
					stats.uniqueFingerprints = graph.nodes.filter((n) => n.type === "FINGERPRINT").length;

					return jsonResponse(stats);
				}

				default:
					throw new APIError(404, "Not found");
			}
		} catch (error) {
			return errorResponse(error as Error);
		}
	},
};
