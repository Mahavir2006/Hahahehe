import { getBytes, keccak256 as ethersKeccak256 } from 'ethers';
/**
 * Canonical JSON and cryptographic utilities for CascadeShield (TypeScript).
 * This mirrors backend/common/crypto.py for cross-language verification.
 */

export interface CanonicalConfig {
  sortKeys: boolean;
  ensureAscii: boolean;
  separators: [string, string];
  normalizeNumbers: boolean;
}

export const DEFAULT_CONFIG: CanonicalConfig = {
  sortKeys: true,
  ensureAscii: false,
  separators: [',', ':'],
  normalizeNumbers: true,
};

/**
 * Normalize a number for canonical JSON.
 * - Integers stay as integers
 * - Floats with .0 become integers
 * - Floats lose trailing zeros
 */
function normalizeNumber(value: number): number {
  if (Number.isInteger(value)) {
    return value;
  }
  // Remove trailing zeros
  const str = value.toString();
  if (str.includes('.')) {
    return parseFloat(str.replace(/\.?0+$/, ''));
  }
  return value;
}

/**
 * Process a value for canonical JSON serialization.
 */
function processValue(value: unknown, config: CanonicalConfig): unknown {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'number') {
    return config.normalizeNumbers ? normalizeNumber(value) : value;
  }
  if (typeof value === 'string') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map(v => processValue(v, config));
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const sortedKeys = Object.keys(obj).sort();
    const result: Record<string, unknown> = {};
    for (const key of sortedKeys) {
      result[key] = processValue(obj[key], config);
    }
    return result;
  }
  // Fallback for other types (BigInt, etc.)
  return String(value);
}

/**
 * Produce canonical JSON string for an object.
 */
export function canonicalJson(value: unknown, config: CanonicalConfig = DEFAULT_CONFIG): string {
  const processed = processValue(value, config);
  // JSON.stringify without an indent argument is already compact; never strip whitespace inside string values.
  return JSON.stringify(processed);
}

/**
 * Compute SHA-256 hash of canonical JSON representation.
 * Returns hex string.
 */
export async function canonicalHash(value: unknown, config: CanonicalConfig = DEFAULT_CONFIG): Promise<string> {
  const canon = canonicalJson(value, config);
  const encoder = new TextEncoder();
  const data = encoder.encode(canon);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA-256 hash as bytes.
 */
export async function canonicalHashBytes(value: unknown, config: CanonicalConfig = DEFAULT_CONFIG): Promise<Uint8Array> {
  const canon = canonicalJson(value, config);
  const encoder = new TextEncoder();
  const data = encoder.encode(canon);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

// ============================================================================
// EIP-712 Domain Separator and Typed Data Hashing
// ============================================================================

export interface EIP712Domain {
  name: string;
  version: string;
  chainId: number;
  verifyingContract: string; // checksummed address
}

/**
 * Compute keccak256 hash.
 */
async function keccak256(data: Uint8Array): Promise<Uint8Array> {
  // Ethereum keccak256 (not WebCrypto SHA-3, which is a different function and not available in browsers)
  return getBytes(ethersKeccak256(data));
}

/**
 * Compute EIP-712 domain separator.
 */
export async function eip712DomainSeparator(domain: EIP712Domain): Promise<Uint8Array> {
  const domainTypeHash = await keccak256(
    new TextEncoder().encode('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
  );
  
  const nameHash = await keccak256(new TextEncoder().encode(domain.name));
  const versionHash = await keccak256(new TextEncoder().encode(domain.version));
  
  // Pack chainId as uint256 (32 bytes)
  const chainIdBytes = new Uint8Array(32);
  let chainId = domain.chainId;
  for (let i = 31; i >= 0; i--) {
    chainIdBytes[i] = chainId & 0xff;
    chainId >>= 8;
  }
  
  // Pack verifyingContract as address (20 bytes, left-padded to 32)
  const contractHex = domain.verifyingContract.startsWith('0x') 
    ? domain.verifyingContract.slice(2) 
    : domain.verifyingContract;
  const contractBytes = new Uint8Array(contractHex.match(/.{1,2}/g)!.map(b => parseInt(b, 16)));
  const contractPadded = new Uint8Array(32);
  contractPadded.set(contractBytes, 12); // Left pad to 32 bytes
  
  const combined = new Uint8Array(
    domainTypeHash.length + nameHash.length + versionHash.length + 
    chainIdBytes.length + contractPadded.length
  );
  let offset = 0;
  combined.set(domainTypeHash, offset); offset += domainTypeHash.length;
  combined.set(nameHash, offset); offset += nameHash.length;
  combined.set(versionHash, offset); offset += versionHash.length;
  combined.set(chainIdBytes, offset); offset += chainIdBytes.length;
  combined.set(contractPadded, offset);
  
  return keccak256(combined);
}

/**
 * Compute type hash for a struct type definition.
 */
export async function eip712TypeHash(typeDefinition: string): Promise<Uint8Array> {
  return keccak256(new TextEncoder().encode(typeDefinition));
}

/**
 * Encode struct data for EIP-712 (simplified - uses eth-abi in practice).
 * This is a placeholder; real implementation uses eth-abi encoding.
 */
export async function eip712EncodeData(
  _typeHash: Uint8Array, 
  _fields: Array<[string, string]>, 
  _values: unknown[]
): Promise<Uint8Array> {
  // In practice, use eth-abi for proper encoding
  // This is a stub for the interface
  throw new Error('Use eth-abi library for proper EIP-712 encoding');
}

/**
 * Compute the final signable hash per EIP-712.
 */
export async function eip712SignableHash(
  domain: EIP712Domain,
  _typeHash: Uint8Array,
  structData: Uint8Array
): Promise<Uint8Array> {
  const domainSep = await eip712DomainSeparator(domain);
  const prefix = new Uint8Array([0x19, 0x01]);
  const combined = new Uint8Array(prefix.length + domainSep.length + structData.length);
  combined.set(prefix, 0);
  combined.set(domainSep, prefix.length);
  combined.set(structData, prefix.length + domainSep.length);
  return keccak256(combined);
}

// ============================================================================
// Merkle Tree for Audit Log Batching
// ============================================================================

/**
 * Compute Merkle root from list of leaf hashes (Uint8Array 32 bytes each).
 */
export async function merkleRoot(leaves: Uint8Array[]): Promise<Uint8Array> {
  if (leaves.length === 0) {
    return new Uint8Array(32);
  }
  
  let currentLevel = leaves;
  while (currentLevel.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left, 0);
      combined.set(right, left.length);
      nextLevel.push(await keccak256(combined));
    }
    currentLevel = nextLevel;
  }
  return currentLevel[0];
}

/**
 * Generate Merkle proof for leaf at index.
 */
export async function merkleProof(leaves: Uint8Array[], index: number): Promise<Uint8Array[]> {
  const proof: Uint8Array[] = [];
  let currentLevel = leaves;
  let currentIndex = index;
  
  while (currentLevel.length > 1) {
    const nextLevel: Uint8Array[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const left = currentLevel[i];
      const right = i + 1 < currentLevel.length ? currentLevel[i + 1] : currentLevel[i];
      
      if (i === currentIndex || i + 1 === currentIndex) {
        const sibling = i === currentIndex ? right : left;
        proof.push(sibling);
        currentIndex = Math.floor(i / 2);
      }
      
      const combined = new Uint8Array(left.length + right.length);
      combined.set(left, 0);
      combined.set(right, left.length);
      nextLevel.push(await keccak256(combined));
    }
    currentLevel = nextLevel;
  }
  
  return proof;
}

/**
 * Verify a Merkle proof.
 */
export async function verifyMerkleProof(
  root: Uint8Array,
  leaf: Uint8Array,
  proof: Uint8Array[],
  index: number
): Promise<boolean> {
  let current = leaf;
  let currentIndex = index;
  
  for (const sibling of proof) {
    const combined = new Uint8Array(current.length + sibling.length);
    if (currentIndex % 2 === 0) {
      combined.set(current, 0);
      combined.set(sibling, current.length);
    } else {
      combined.set(sibling, 0);
      combined.set(current, sibling.length);
    }
    current = await keccak256(combined);
    currentIndex = Math.floor(currentIndex / 2);
  }
  
  return current.length === root.length && current.every((v, i) => v === root[i]);
}

// ============================================================================
// Test Vectors (must match Python implementation)
// ============================================================================

export const TEST_VECTORS: Array<[unknown, string]> = [
  [{"a": 1, "b": 2}, '{"a":1,"b":2}'],
  [{"b": {"z": 1, "a": 2}, "a": 3}, '{"a":3,"b":{"a":2,"z":1}}'],
  [[3, 1, 2], '[3,1,2]'],
  [{"items": [{"id": 2}, {"id": 1}], "count": 2}, '{"count":2,"items":[{"id":2},{"id":1}]}'],
  [{"int": 42, "float": 3.1400, "sci": 1e3}, '{"float":3.14,"int":42,"sci":1000}'],
  [{}, '{}'],
  [[], '[]'],
  [{"msg": "hello \u00e9"}, '{"msg":"hello \u00e9"}'],
];

/**
 * Run test vectors and verify cross-language compatibility.
 */
export async function runTestVectors(): Promise<boolean> {
  for (const [obj, expected] of TEST_VECTORS) {
    const result = canonicalJson(obj);
    if (result !== expected) {
      console.error('FAIL:', obj);
      console.error('  Expected:', expected);
      console.error('  Got:     ', result);
      return false;
    }
  }
  console.log('All canonical JSON test vectors passed!');
  return true;
}
