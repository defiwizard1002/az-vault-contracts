import * as fs from 'fs';
import * as path from 'path';

const outDir = path.join(__dirname, '../out');
const contractPath = path.join(outDir, 'AssetVault.sol', 'AssetVault.json');

if (!fs.existsSync(contractPath)) {
  console.error(`Contract artifact not found: ${contractPath}`);
  console.error('Please run "forge build" first');
  process.exit(1);
}

const artifact = JSON.parse(fs.readFileSync(contractPath, 'utf-8'));

let bytecode: string | undefined;
let deployedBytecode: string | undefined;

if (artifact.bytecode && typeof artifact.bytecode === 'object' && artifact.bytecode.object) {
  bytecode = artifact.bytecode.object;
} else if (typeof artifact.bytecode === 'string') {
  bytecode = artifact.bytecode;
}

if (artifact.deployedBytecode && typeof artifact.deployedBytecode === 'object' && artifact.deployedBytecode.object) {
  deployedBytecode = artifact.deployedBytecode.object;
} else if (typeof artifact.deployedBytecode === 'string') {
  deployedBytecode = artifact.deployedBytecode;
}

if (!bytecode && !deployedBytecode) {
  console.error('Bytecode not found in artifact');
  console.error('Available keys:', Object.keys(artifact).join(', '));
  process.exit(1);
}

const calculateSize = (code: string): number => {
  const cleaned = code.startsWith('0x') ? code.slice(2) : code;
  return cleaned.length / 2;
};

if (bytecode) {
  const size = calculateSize(bytecode);
  console.log(`Contract Bytecode Size: ${size} bytes (${(size / 1024).toFixed(2)} KB)`);
  console.log(`  Hex length: ${bytecode.length} characters`);
}

if (deployedBytecode) {
  const size = calculateSize(deployedBytecode);
  console.log(`Deployed Bytecode Size: ${size} bytes (${(size / 1024).toFixed(2)} KB)`);
  console.log(`  Hex length: ${deployedBytecode.length} characters`);
}

const evmLimit = 24576;
if (deployedBytecode) {
  const size = calculateSize(deployedBytecode);
  const remaining = evmLimit - size;
  console.log(`\nEVM Limit: ${evmLimit} bytes`);
  console.log(`Remaining: ${remaining} bytes (${(remaining / 1024).toFixed(2)} KB)`);
  if (size > evmLimit) {
    console.log(`⚠️  WARNING: Contract exceeds EVM limit by ${size - evmLimit} bytes!`);
  }
}

