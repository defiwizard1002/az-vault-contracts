import * as fs from 'fs';
import * as path from 'path';
import { execSync } from 'child_process';

const broadcastDir = path.join(__dirname, '../broadcast');
const deploymentsDir = path.join(__dirname, '../deployments');
const outDir = path.join(__dirname, '../out');
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

if (!fs.existsSync(deploymentsDir)) {
  console.error(`  ❌ Deployments directory does not exist: ${deploymentsDir}`);
  process.exit(1);
}

if (!fs.existsSync(artifactsDir)) {
  fs.mkdirSync(artifactsDir, { recursive: true });
}

if (!fs.existsSync(typesDir)) {
  fs.mkdirSync(typesDir, { recursive: true });
}

const contractNames = new Set<string>();

for (const chainId in deployments) {
  for (const contractName in deployments[chainId]) {
    const name = contractName.replace('Proxy', '');
    contractNames.add(name);
  }
}

console.log(`  Found ${contractNames.size} contracts from deployments:`, Array.from(contractNames));

const artifactFiles: string[] = [];

for (const contractName of contractNames) {
  const deploymentsAbiPath = path.join(deploymentsDir, `${contractName}.json`);
  const outAbiPath = path.join(outDir, `${contractName}.sol`, `${contractName}.json`);
  
  let abi: any[] | null = null;
  let abiPath: string | null = null;
  
  if (fs.existsSync(deploymentsAbiPath)) {
    abiPath = deploymentsAbiPath;
    abi = JSON.parse(fs.readFileSync(deploymentsAbiPath, 'utf-8'));
  } else if (fs.existsSync(outAbiPath)) {
    abiPath = outAbiPath;
    const artifact = JSON.parse(fs.readFileSync(outAbiPath, 'utf-8'));
    abi = artifact.abi;
    const deploymentsAbiOutput = path.join(deploymentsDir, `${contractName}.json`);
    fs.writeFileSync(deploymentsAbiOutput, JSON.stringify(abi, null, 2));
    console.log(`  ✓ Extracted ABI for ${contractName} from out/`);
  }
  
  if (abi && Array.isArray(abi)) {
    const artifact = {
      abi: abi,
      contractName: contractName,
      sourceName: `${contractName}.sol`
    };
    
    const artifactPath = path.join(artifactsDir, `${contractName}.json`);
    fs.writeFileSync(artifactPath, JSON.stringify(artifact, null, 2));
    artifactFiles.push(artifactPath);
    console.log(`  ✓ Prepared artifact for ${contractName}`);
  } else {
    console.error(`  ❌ Could not find ABI for ${contractName}`);
  }
}

if (artifactFiles.length === 0) {
  console.error('  ❌ No artifacts were prepared');
  process.exit(1);
}

console.log(`\nStep 3: Running TypeChain...`);

const files = artifactFiles.join(' ');

try {
  const cmd = `npx --yes typechain --out-dir ${typesDir} ${files} --target ethers-v6`;
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
