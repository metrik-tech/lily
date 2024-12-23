import { nanoid } from "nanoid";

export interface NodeProperties {
	[key: string]: any;
}

export interface Edge {
	id: string;
	type: string;
	properties: Record<string, any>;
	fromNodeId: string;
	toNodeId: string;
}

export interface Node {
	id: string;
	properties: NodeProperties;
	inEdges: string[];
	outEdges: string[];
}

export interface QueryOptions {
	type?: string;
	property?: string;
	value?: any;
	limit?: number;
	cursor?: string;
}

export interface QueryResult<T> {
	items: T[];
	cursor?: string;
	hasMore: boolean;
}

export class GraphDatabase {
	private readonly kv: KVNamespace;
	private readonly NODE_PREFIX: string;
	private readonly EDGE_PREFIX: string;
	private readonly INDEX_PREFIX: string;
	private readonly BATCH_SIZE: number;

	constructor(
		kv: KVNamespace,
		options: {
			nodePrefix?: string;
			edgePrefix?: string;
			indexPrefix?: string;
			batchSize?: number;
		} = {}
	) {
		this.kv = kv;
		this.NODE_PREFIX = options.nodePrefix || "node:";
		this.EDGE_PREFIX = options.edgePrefix || "edge:";
		this.INDEX_PREFIX = options.indexPrefix || "index:";
		this.BATCH_SIZE = options.batchSize || 100;
	}

	async createNode(properties: NodeProperties): Promise<Node> {
		const nodeId = nanoid(14);
		const node: Node = {
			id: nodeId,
			properties,
			inEdges: [],
			outEdges: [],
		};

		await this.kv.put(`${this.NODE_PREFIX}${nodeId}`, JSON.stringify(node));

		const indexPromises = Object.entries(properties).map(([key, value]) =>
			this.kv.put(`${this.INDEX_PREFIX}${key}:${value}:${nodeId}`, JSON.stringify({ nodeId, value }))
		);

		await Promise.all(indexPromises);
		return node;
	}

	async getNode(nodeId: string): Promise<Node | null> {
		const node = await this.kv.get(`${this.NODE_PREFIX}${nodeId}`);
		return node ? JSON.parse(node) : null;
	}

	async updateNode(nodeId: string, properties: Partial<NodeProperties>): Promise<Node | null> {
		const node = await this.getNode(nodeId);
		if (!node) return null;

		const deletePromises = Object.entries(node.properties).map(([key, value]) =>
			this.kv.delete(`${this.INDEX_PREFIX}${key}:${value}:${nodeId}`)
		);

		node.properties = { ...node.properties, ...properties };

		const indexPromises = Object.entries(node.properties).map(([key, value]) =>
			this.kv.put(`${this.INDEX_PREFIX}${key}:${value}:${nodeId}`, JSON.stringify({ nodeId, value }))
		);

		await Promise.all([...deletePromises, ...indexPromises, this.kv.put(`${this.NODE_PREFIX}${nodeId}`, JSON.stringify(node))]);

		return node;
	}

	async deleteNode(nodeId: string): Promise<boolean> {
		const node = await this.getNode(nodeId);
		if (!node) return false;

		const edgePromises = [...node.inEdges, ...node.outEdges].map((edgeId) => this.deleteEdge(edgeId));

		const indexPromises = Object.entries(node.properties).map(([key, value]) =>
			this.kv.delete(`${this.INDEX_PREFIX}${key}:${value}:${nodeId}`)
		);

		await Promise.all([...edgePromises, ...indexPromises, this.kv.delete(`${this.NODE_PREFIX}${nodeId}`)]);

		return true;
	}

	async createEdge(fromNodeId: string, toNodeId: string, type: string, properties: Record<string, any> = {}): Promise<Edge> {
		const [fromNode, toNode] = await Promise.all([this.getNode(fromNodeId), this.getNode(toNodeId)]);

		if (!fromNode || !toNode) {
			throw new Error("Source or target node not found");
		}

		const edgeId = nanoid(14);
		const edge: Edge = {
			id: edgeId,
			type,
			properties,
			fromNodeId,
			toNodeId,
		};

		fromNode.outEdges.push(edgeId);
		toNode.inEdges.push(edgeId);

		await Promise.all([
			this.kv.put(`${this.EDGE_PREFIX}${edgeId}`, JSON.stringify(edge)),
			this.kv.put(`${this.NODE_PREFIX}${fromNodeId}`, JSON.stringify(fromNode)),
			this.kv.put(`${this.NODE_PREFIX}${toNodeId}`, JSON.stringify(toNode)),
		]);

		return edge;
	}

	async getEdge(edgeId: string): Promise<Edge | null> {
		const edge = await this.kv.get(`${this.EDGE_PREFIX}${edgeId}`);
		return edge ? JSON.parse(edge) : null;
	}

	async updateEdge(edgeId: string, properties: Record<string, any>): Promise<Edge | null> {
		const edge = await this.getEdge(edgeId);
		if (!edge) return null;

		edge.properties = { ...edge.properties, ...properties };
		await this.kv.put(`${this.EDGE_PREFIX}${edgeId}`, JSON.stringify(edge));
		return edge;
	}

	async deleteEdge(edgeId: string): Promise<boolean> {
		const edge = await this.getEdge(edgeId);
		if (!edge) return false;

		const [fromNode, toNode] = await Promise.all([this.getNode(edge.fromNodeId), this.getNode(edge.toNodeId)]);

		if (fromNode) {
			fromNode.outEdges = fromNode.outEdges.filter((id) => id !== edgeId);
			await this.kv.put(`${this.NODE_PREFIX}${edge.fromNodeId}`, JSON.stringify(fromNode));
		}

		if (toNode) {
			toNode.inEdges = toNode.inEdges.filter((id) => id !== edgeId);
			await this.kv.put(`${this.NODE_PREFIX}${edge.toNodeId}`, JSON.stringify(toNode));
		}

		await this.kv.delete(`${this.EDGE_PREFIX}${edgeId}`);
		return true;
	}

	async query(options: QueryOptions = {}): Promise<QueryResult<Node>> {
		const { type, property, value, limit = this.BATCH_SIZE, cursor } = options;
		let prefix = this.INDEX_PREFIX;

		if (type) prefix += `type:${type}:`;
		else if (property && value !== undefined) prefix += `${property}:${value}:`;

		const listResult = await this.kv.list({
			prefix,
			limit: limit + 1, // Request one extra to check if there are more
			cursor,
		});

		const nodeIds = listResult.keys.slice(0, limit).map((key) => key.name.split(":").pop() as string);

		const nodePromises = nodeIds.map((id) => this.getNode(id));
		const nodes = await Promise.all(nodePromises);
		const validNodes = nodes.filter((node): node is Node => node !== null);

		return {
			items: validNodes,
			cursor: !listResult.list_complete ? listResult.cursor : undefined,
			hasMore: !listResult.list_complete && listResult.keys.length > limit,
		};
	}

	async getConnectedNodes(nodeId: string, direction: "in" | "out", edgeType?: string): Promise<Node[]> {
		const node = await this.getNode(nodeId);
		if (!node) return [];

		const edgeIds = direction === "out" ? node.outEdges : node.inEdges;
		const edges = await Promise.all(edgeIds.map((id) => this.getEdge(id)));
		const validEdges = edges.filter((edge): edge is Edge => edge !== null && (!edgeType || edge.type === edgeType));

		const connectedNodeIds = validEdges.map((edge) => (direction === "out" ? edge.toNodeId : edge.fromNodeId));

		const nodes = await Promise.all(connectedNodeIds.map((id) => this.getNode(id)));
		return nodes.filter((node): node is Node => node !== null);
	}

	async traverse(
		startNodeId: string,
		options: {
			maxDepth?: number;
			direction?: "in" | "out" | "both";
			edgeType?: string;
		} = {}
	): Promise<Node[]> {
		const { maxDepth = 3, direction = "out", edgeType } = options;

		const visited = new Set<string>();
		const result: Node[] = [];

		async function* traverseNodes(this: GraphDatabase, nodeId: string, depth: number): AsyncGenerator<Node> {
			if (depth >= maxDepth || visited.has(nodeId)) return;

			visited.add(nodeId);
			const node = await this.getNode(nodeId);
			if (!node) return;

			yield node;
			result.push(node);

			const directions = direction === "both" ? ["in", "out"] : [direction];
			for (const dir of directions) {
				const connected = await this.getConnectedNodes(nodeId, dir as "in" | "out", edgeType);
				for (const nextNode of connected) {
					yield* traverseNodes.call(this, nextNode.id, depth + 1);
				}
			}
		}

		for await (const node of traverseNodes.call(this, startNodeId, 0)) {
			// Traversal happens through the generator
		}

		return result;
	}
}
