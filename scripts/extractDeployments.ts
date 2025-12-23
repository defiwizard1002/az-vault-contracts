import * as fs from 'fs';
import * as path from 'path';

const broadcastDir = path.join(__dirname, '../broadcast');
const deploymentsDir = path.join(__dirname, '../deployments');
const outDir = path.join(__dirname, '../out');

fs.mkdirSync(deploymentsDir, { recursive: true });

const deployments: Record<string, Record<string, { name: string; address: string }[]>> = {};

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
    
    if (!deployments[chainId]) {
      deployments[chainId] = {};
    }

    const transactions = runData.transactions || [];
    for (let i = 0; i < transactions.length; i++) {
      const tx = transactions[i];
      
      if (tx.transactionType === 'CREATE' && tx.contractName && tx.contractAddress) {
        const contractName = tx.contractName;
        const contractAddress = tx.contractAddress.toLowerCase();

        if (contractName === 'ERC1967Proxy') {
          if (i > 0 && transactions[i - 1].transactionType === 'CREATE' && transactions[i - 1].contractName) {
            const implContractName = transactions[i - 1].contractName;
            const proxyName = `${implContractName}Proxy`;
            
            if (!deployments[chainId][proxyName]) {
              deployments[chainId][proxyName] = [];
            }

            const exists = deployments[chainId][proxyName].some(
              (d: any) => d.address.toLowerCase() === contractAddress
            );

            if (!exists) {
              deployments[chainId][proxyName].push({
                name: proxyName,
                address: contractAddress
              });
            }
          }
        } else {
          if (!deployments[chainId][contractName]) {
            deployments[chainId][contractName] = [];
          }

          const exists = deployments[chainId][contractName].some(
            (d: any) => d.address.toLowerCase() === contractAddress
          );

          if (!exists) {
            deployments[chainId][contractName].push({
              name: contractName,
              address: contractAddress
            });
          }

          const abiPath = path.join(outDir, `${contractName}.sol`, `${contractName}.json`);
          if (fs.existsSync(abiPath)) {
            const artifact = JSON.parse(fs.readFileSync(abiPath, 'utf-8'));
            const abiOutputPath = path.join(deploymentsDir, `${contractName}.json`);
            fs.writeFileSync(abiOutputPath, JSON.stringify(artifact.abi, null, 2), 'utf-8');
          }
        }
      }
    }
  }
}

const deploymentsJsonPath = path.join(deploymentsDir, 'deployments.json');
fs.writeFileSync(deploymentsJsonPath, JSON.stringify(deployments, null, 2), 'utf-8');

console.log(`Deployments info written to: ${deploymentsJsonPath}`);
