require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');

async function main() {
  const connectionString = process.env.DATABASE_URL || 'postgres://cyberguard:cyberguard@localhost:5432/cyberguard';
  const sqlPath = path.join(__dirname, '..', '..', '..', 'database', 'init.sql');
  const sql = fs.readFileSync(sqlPath, 'utf8');

  const client = new Client({ connectionString });
  await client.connect();
  console.log(`[db:init] Connected to ${connectionString.replace(/:[^:@]*@/, ':****@')}`);
  try {
    await client.query(sql);
    console.log('[db:init] Schema applied successfully (tables created if not already present).');
  } finally {
    await client.end();
  }
}

main().catch((err) => {
  console.error('[db:init] Failed:', err.message);
  process.exit(1);
});
