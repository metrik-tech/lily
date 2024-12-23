import { GraphDatabase, Node, Edge } from "./graph";
import { UAParser } from "ua-parser-js";

export interface ConnectionStats {
	firstSeen: string;
	lastSeen: string;
	count: number;
}

export interface DeviceMetadata {
	browser: string;
	browserVersion: string;
	os: string;
	osVersion: string;
	device: string;
	deviceType: string;
	cpu: string;
	userAgent: string;
}

export interface UserConnection {
	ips: Array<{
		ip: string;
		stats: ConnectionStats;
	}>;
	fingerprints: Array<{
		fingerprint: string;
		metadata?: DeviceMetadata;
		stats: ConnectionStats;
	}>;
}

export interface ConnectionsResponse {
	nodes: Array<{
		id: string;
		type: "USER" | "IP" | "FINGERPRINT";
		label: string;
		risk?: "LOW" | "MEDIUM" | "HIGH";
		riskScore?: number;
		metadata?: DeviceMetadata;
		stats: ConnectionStats;
	}>;
	links: Array<{
		source: string;
		target: string;
		type: string;
		stats: ConnectionStats;
	}>;
}

interface RiskFactor {
	score: number;
	reason: string;
	details: any;
}

interface RiskAssessment {
	score: number;
	level: "LOW" | "MEDIUM" | "HIGH";
	factors: RiskFactor[];
}

export class UserTracker {
	private db: GraphDatabase;
	private parser: UAParser;

	constructor(kv: KVNamespace) {
		this.db = new GraphDatabase(kv);
		this.parser = new UAParser();
	}

	async recordConnection(
		userId: string,
		ip: string,
		fingerprint: string,
		userAgent: string,
		timestamp: string = new Date().toISOString()
	): Promise<void> {
		const [userNode, ipNode, fpNode] = await Promise.all([
			this.getOrCreateUserNode(userId, timestamp),
			this.getOrCreateIPNode(ip, timestamp),
			this.getOrCreateFingerprintNode(fingerprint, userAgent, timestamp),
		]);

		await Promise.all([
			this.updateConnection(userNode.id, ipNode.id, "USES_IP", timestamp),
			this.updateConnection(userNode.id, fpNode.id, "USES_FINGERPRINT", timestamp),
		]);
	}

	async getConnectionGraph(
		options: {
			hours?: number;
			riskThreshold?: number;
		} = {}
	): Promise<ConnectionsResponse> {
		const { hours = 24, riskThreshold = 0 } = options;
		const cutoffTime = new Date(Date.now() - hours * 60 * 60 * 1000).toISOString();

		const users = await this.db.query({ type: "USER" });
		const nodes: ConnectionsResponse["nodes"] = [];
		const links: ConnectionsResponse["links"] = [];
		const seenNodes = new Set<string>();
		const seenLinks = new Set<string>();

		for (const user of users.items) {
			const [ipEdges, fpEdges] = await Promise.all([
				this.getNodeConnections(user, "USES_IP"),
				this.getNodeConnections(user, "USES_FINGERPRINT"),
			]);

			const { score: riskScore } = this.calculateUserRisk(ipEdges, fpEdges);
			if (riskScore < riskThreshold) continue;

			const hasRecentConnections = [...ipEdges, ...fpEdges].some((edge) => edge.stats.lastSeen >= cutoffTime);

			if (hasRecentConnections) {
				nodes.push({
					id: user.id,
					type: "USER",
					label: user.properties.userId,
					risk: this.getRiskLevel(riskScore),
					riskScore,
					stats: {
						firstSeen: user.properties.firstSeen,
						lastSeen: user.properties.lastSeen,
						count: ipEdges.length + fpEdges.length,
					},
				});
				seenNodes.add(user.id);

				for (const edge of ipEdges) {
					if (edge.stats.lastSeen >= cutoffTime) {
						const ipNode = {
							id: edge.node.id,
							type: "IP" as const,
							label: edge.node.properties.ip,
							stats: edge.stats,
						};

						if (!seenNodes.has(edge.node.id)) {
							nodes.push(ipNode);
							seenNodes.add(edge.node.id);
						}

						const linkId = `${user.id}-${edge.node.id}`;
						if (!seenLinks.has(linkId)) {
							links.push({
								source: user.id,
								target: edge.node.id,
								type: "USES_IP",
								stats: edge.stats,
							});
							seenLinks.add(linkId);
						}
					}
				}

				for (const edge of fpEdges) {
					if (edge.stats.lastSeen >= cutoffTime) {
						const fpNode = {
							id: edge.node.id,
							type: "FINGERPRINT" as const,
							label: edge.node.properties.fingerprint,
							metadata: edge.node.properties.metadata,
							stats: edge.stats,
						};

						if (!seenNodes.has(edge.node.id)) {
							nodes.push(fpNode);
							seenNodes.add(edge.node.id);
						}

						const linkId = `${user.id}-${edge.node.id}`;
						if (!seenLinks.has(linkId)) {
							links.push({
								source: user.id,
								target: edge.node.id,
								type: "USES_FINGERPRINT",
								stats: edge.stats,
							});
							seenLinks.add(linkId);
						}
					}
				}
			}
		}

		return { nodes, links };
	}

	async getUserConnections(userId: string): Promise<UserConnection> {
		const users = await this.db.query({
			type: "USER",
			property: "userId",
			value: userId,
		});

		if (users.items.length === 0) {
			return { ips: [], fingerprints: [] };
		}

		const userNode = users.items[0];
		const [ipConns, fpConns] = await Promise.all([
			this.getNodeConnections(userNode, "USES_IP"),
			this.getNodeConnections(userNode, "USES_FINGERPRINT"),
		]);

		return {
			ips: ipConns.map((conn) => ({
				ip: conn.node.properties.ip,
				stats: conn.stats,
			})),
			fingerprints: fpConns.map((conn) => ({
				fingerprint: conn.node.properties.fingerprint,
				metadata: conn.node.properties.metadata,
				stats: conn.stats,
			})),
		};
	}

	private async getOrCreateUserNode(userId: string, timestamp: string): Promise<Node> {
		const users = await this.db.query({
			type: "USER",
			property: "userId",
			value: userId,
		});

		if (users.items.length > 0) {
			const user = users.items[0];
			await this.db.updateNode(user.id, { lastSeen: timestamp });
			return user;
		}

		return this.db.createNode({
			type: "USER",
			userId,
			firstSeen: timestamp,
			lastSeen: timestamp,
		});
	}

	private async getOrCreateIPNode(ip: string, timestamp: string): Promise<Node> {
		const ips = await this.db.query({
			type: "IP",
			property: "ip",
			value: ip,
		});

		if (ips.items.length > 0) {
			const ipNode = ips.items[0];
			await this.db.updateNode(ipNode.id, { lastSeen: timestamp });
			return ipNode;
		}

		return this.db.createNode({
			type: "IP",
			ip,
			firstSeen: timestamp,
			lastSeen: timestamp,
		});
	}

	private async getOrCreateFingerprintNode(fingerprint: string, userAgent: string, timestamp: string): Promise<Node> {
		const fps = await this.db.query({
			type: "FINGERPRINT",
			property: "fingerprint",
			value: fingerprint,
		});

		if (fps.items.length > 0) {
			const fpNode = fps.items[0];
			await this.db.updateNode(fpNode.id, { lastSeen: timestamp });
			return fpNode;
		}

		this.parser.setUA(userAgent);
		const result = this.parser.getResult();

		return this.db.createNode({
			type: "FINGERPRINT",
			fingerprint,
			firstSeen: timestamp,
			lastSeen: timestamp,
			metadata: {
				browser: result.browser.name || "Unknown",
				browserVersion: result.browser.version || "Unknown",
				os: result.os.name || "Unknown",
				osVersion: result.os.version || "Unknown",
				device: result.device.model || "Unknown",
				deviceType: result.device.type || "desktop",
				cpu: result.cpu.architecture || "Unknown",
				userAgent,
			},
		});
	}

	private async updateConnection(fromNodeId: string, toNodeId: string, type: string, timestamp: string): Promise<void> {
		const fromNode = await this.db.getNode(fromNodeId);
		if (!fromNode) throw new Error("Source node not found");

		const edge = await this.findEdge(fromNode.outEdges, type, toNodeId);

		if (edge) {
			await this.db.updateEdge(edge.id, {
				lastSeen: timestamp,
				count: (edge.properties.count || 0) + 1,
			});
		} else {
			await this.db.createEdge(fromNodeId, toNodeId, type, {
				firstSeen: timestamp,
				lastSeen: timestamp,
				count: 1,
			});
		}
	}

	private async findEdge(edgeIds: string[], type: string, toNodeId: string): Promise<Edge | null> {
		for (const edgeId of edgeIds) {
			const edge = await this.db.getEdge(edgeId);
			if (edge && edge.type === type && edge.toNodeId === toNodeId) {
				return edge;
			}
		}
		return null;
	}

	private async getNodeConnections(
		node: Node,
		type: string
	): Promise<
		Array<{
			node: Node;
			stats: ConnectionStats;
		}>
	> {
		const edges = await Promise.all(node.outEdges.map((id) => this.db.getEdge(id)));

		const connections: Array<{
			node: Node;
			stats: ConnectionStats;
		}> = [];

		for (const edge of edges) {
			if (!edge || edge.type !== type) continue;

			const targetNode = await this.db.getNode(edge.toNodeId);
			if (!targetNode) continue;

			connections.push({
				node: targetNode,
				stats: edge.properties as ConnectionStats,
			});
		}

		return connections;
	}

	private calculateUserRisk(
		ipEdges: Array<{ node: Node; stats: ConnectionStats }>,
		fpEdges: Array<{ node: Node; stats: ConnectionStats }>
	): RiskAssessment {
		const factors: RiskFactor[] = [];
		let totalScore = 0;

		// Time windows for analysis
		const now = new Date().getTime();
		const last24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
		const last1h = new Date(now - 60 * 60 * 1000).toISOString();
		const last5m = new Date(now - 5 * 60 * 1000).toISOString();

		// 1. Recent IP Changes (24h)
		const recentIPs = ipEdges.filter((e) => e.stats.lastSeen >= last24h);
		const uniqueIPs = new Set(recentIPs.map((e) => e.node.properties.ip));

		if (uniqueIPs.size > 3) {
			factors.push({
				score: Math.min(uniqueIPs.size * 10, 30),
				reason: "Multiple IPs in 24 hours",
				details: {
					uniqueIPs: uniqueIPs.size,
					ips: Array.from(uniqueIPs),
				},
			});
		}

		// 2. Rapid IP Changes (1h)
		const ipChangesLast1h = new Set(ipEdges.filter((e) => e.stats.lastSeen >= last1h).map((e) => e.node.properties.ip)).size;

		if (ipChangesLast1h > 2) {
			factors.push({
				score: Math.min(ipChangesLast1h * 15, 40),
				reason: "Rapid IP switching",
				details: {
					changesLastHour: ipChangesLast1h,
				},
			});
		}

		// 3. Fingerprint Changes (24h)
		const recentFingerprints = fpEdges.filter((e) => e.stats.lastSeen >= last24h);
		const uniqueFingerprints = new Set(recentFingerprints.map((e) => e.node.properties.fingerprint));

		if (uniqueFingerprints.size > 2) {
			factors.push({
				score: Math.min(uniqueFingerprints.size * 15, 35),
				reason: "Multiple fingerprints in 24 hours",
				details: {
					uniqueFingerprints: uniqueFingerprints.size,
				},
			});
		}

		// 4. Very Rapid Changes (5m)
		const rapidChanges = this.checkRapidChanges(ipEdges, fpEdges, last5m);
		if (rapidChanges.score > 0) {
			factors.push(rapidChanges);
		}

		// Calculate total score
		totalScore = factors.reduce((sum, factor) => sum + factor.score, 0);
		totalScore = Math.min(totalScore, 100); // Cap at 100

		return {
			score: totalScore,
			level: this.getRiskLevel(totalScore),
			factors,
		};
	}

	private checkRapidChanges(
		ipEdges: Array<{ node: Node; stats: ConnectionStats }>,
		fpEdges: Array<{ node: Node; stats: ConnectionStats }>,
		since: string
	): RiskFactor {
		const recentEvents = [
			...ipEdges.map((e) => ({
				type: "ip" as const,
				ip: e.node.properties.ip,
				timestamp: e.stats.lastSeen,
			})),
			...fpEdges.map((e) => ({
				type: "fp" as const,
				fingerprint: e.node.properties.fingerprint,
				timestamp: e.stats.lastSeen,
			})),
		]
			.filter((e) => e.timestamp >= since)
			.sort((a, b) => a.timestamp.localeCompare(b.timestamp));

		if (recentEvents.length < 2) return { score: 0, reason: "", details: {} };

		let rapidChanges = 0;
		for (let i = 1; i < recentEvents.length; i++) {
			const timeDiff = new Date(recentEvents[i].timestamp).getTime() - new Date(recentEvents[i - 1].timestamp).getTime();
			if (timeDiff < 1000) {
				rapidChanges++;
			}
		}

		if (rapidChanges > 0) {
			return {
				score: Math.min(rapidChanges * 15, 35),
				reason: "Very rapid identity changes",
				details: {
					changes: rapidChanges,
					timeWindow: "5 minutes",
					events: recentEvents,
				},
			};
		}

		return { score: 0, reason: "", details: {} };
	}

	private getRiskLevel(score: number): "LOW" | "MEDIUM" | "HIGH" {
		if (score >= 70) return "HIGH";
		if (score >= 40) return "MEDIUM";
		return "LOW";
	}
}
