import Knex from 'knex';

const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is not set');
}

const knex = Knex({
  client: 'pg',
  connection: connectionString,
  pool: { min: 2, max: 10 },
});

export default knex;
