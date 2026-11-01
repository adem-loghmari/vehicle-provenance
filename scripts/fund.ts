import { solana } from '../src/env.js';

// Devnet SOL is free test money. Each anchor costs 0.000005 SOL, so 0.1 SOL covers
// thousands of demo runs.
const chain = solana();
console.log(`Registry address: ${chain.signer}`);
let balance = await chain.balance();
console.log(`Balance: ${balance} SOL (devnet)`);

if (balance < 0.05) {
  try {
    console.log('Requesting a devnet airdrop...');
    await chain.airdrop(1);
    balance = await chain.balance();
    console.log(`Balance: ${balance} SOL`);
  } catch (err) {
    console.log(`Airdrop refused (${(err as Error).message.split('\n')[0]}).`);
    console.log(`Devnet airdrops now go through the website: paste the address above into https://faucet.solana.com (devnet), then run this again.`);
    process.exit(1);
  }
}
console.log('Ready.');
