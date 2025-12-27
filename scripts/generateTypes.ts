import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

const broadcastDir = path.join(__dirname, '../broadcast');
const deploymentsDir = path.join(__dirname, '../deployments');
const artifactsDir = path.join(__dirname, '../deployments/artifacts');
const typesDir = path.join(__dirname, '../deployments/types');

console.log('Step 1: Extracting latest deployment addresses...');

const deployments: Record<string, Record<string, { address: string; contractName: string }>> = {};

const scriptDirs = fs.readdirSync(broadcastDir, { withFileTypes: true })
  .filter(dirent => dirent.isDirectory())
  .map(dirent => dirent.name);

for (const scriptDir of scriptDirs) {
  const scriptPath = path.join(broadcastDir, scriptDir);
  const chainDirs = fs.readdirSync(scriptPath, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  for (const chainId of chainDirs) {
    const latestRunPath = path.join(scriptPath, chainId, 'run-latest.json');
    
    if (!fs.existsSync(latestRunPath)) continue;

    const runData = JSON.parse(fs.readFileSync(latestRunPath, 'utf-8'));
    const transactions = runData.transactions || [];
    
    let lastContractName: string | null = null;

    for (let i = 0; i < transactions.length; i++) {
      const tx = transactions[i];
      
      if (tx.transactionType === 'CREATE' && tx.contractName && tx.contractAddress) {
        const contractName = tx.contractName;
        const contractAddress = tx.contractAddress.toLowerCase();

        if (contractName === 'ERC1967Proxy') {
          if (lastContractName) {
            const proxyName = `${lastContractName}Proxy`;
            if (!deployments[chainId]) {
              deployments[chainId] = {};
            }
            deployments[chainId][proxyName] = {
              address: contractAddress,
              contractName: proxyName
            };
          }
        } else {
          lastContractName = contractName;
          if (!deployments[chainId]) {
            deployments[chainId] = {};
          }
          deployments[chainId][contractName] = {
            address: contractAddress,
            contractName: contractName
          };
        }
      }
    }
  }
}

fs.writeFileSync(
  path.join(deploymentsDir, 'deployments.json'),
  JSON.stringify(deployments, null, 2)
);
console.log(`  ✓ Extracted deployments for ${Object.keys(deployments).length} chains`);

console.log('\nStep 2: Preparing artifacts...');

if (!fs.existsSync(artifactsDir)) {
  fs.mkdirSync(artifactsDir, { recursive: true });
}

if (!fs.existsSync(typesDir)) {
  fs.mkdirSync(typesDir, { recursive: true });
}

const abiFiles = fs.readdirSync(deploymentsDir)
  .filter(file => file.endsWith('.json') && file !== 'deployments.json');

const artifactFiles: string[] = [];

for (const abiFile of abiFiles) {
  const contractName = abiFile.replace('.json', '');
  const abiPath = path.join(deploymentsDir, abiFile);
  const abi = JSON.parse(fs.readFileSync(abiPath, 'utf-8'));
  
  const artifact = {
    abi: abi,
    contractName: contractName,
    sourceName: `${contractName}.sol`
  };
  
  const artifactPath = path.join(artifactsDir, abiFile);
  fs.writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
  artifactFiles.push(artifactPath);
  console.log(`  ✓ Prepared ${contractName}.json`);
}

console.log(`\nStep 3: Running TypeChain...`);

if (artifactFiles.length === 0) {
  console.log('  ⚠ No artifact files found, skipping type generation');
  process.exit(0);
}

const files = artifactFiles.join(' ');

try {
  const cmd = `npx --yes typechain --out-dir ${typesDir} ${files} --target ethers-v5`;
  execSync(cmd, { stdio: 'inherit', cwd: path.join(__dirname, '..') });
  
  const generatedFiles = fs.readdirSync(typesDir);
  console.log(`\n✅ Success! Generated:`);
  console.log(`  - Deployment addresses: deployments/deployments.json`);
  console.log(`  - Artifacts: ${artifactFiles.length} files in deployments/artifacts/`);
  console.log(`  - TypeScript types: ${generatedFiles.length} files in deployments/types/`);
} catch (error: any) {
  console.error('\n❌ Error:', error.message);
  process.exit(1);
}
