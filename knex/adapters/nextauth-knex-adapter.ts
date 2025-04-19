import { Adapter, AdapterUser, AdapterAccount } from 'next-auth/adapters';
import { Knex } from 'knex';

export function NextAuthKnexAdapter(knex: Knex): Adapter {
  return {
    // USER
    async createUser(data: AdapterUser) {
      const [user] = await knex('User').insert(data).returning('*');
      return user;
    },
    async getUser(id: string) {
      return knex('User').where({ id }).first();
    },
    async getUserByEmail(email) {
      return knex('User').where({ email }).first();
    },
    async updateUser(data) {
      const [user] = await knex('User').where({ id: data.id }).update(data).returning('*');
      return user;
    },
    async deleteUser(id) {
      await knex('User').where({ id }).del();
    },

    // ACCOUNT
    async linkAccount(account: AdapterAccount) {
      const [acc] = await knex('Account').insert(account).returning('*');
      return acc;
    },
    async unlinkAccount({ provider, providerAccountId }: { provider: string; providerAccountId: string }) {
      await knex('Account').where({ provider, providerAccountId }).del();
    },
    async getUserByAccount({ provider, providerAccountId }: { provider: string; providerAccountId: string }) {
      return knex('Account')
        .where({ provider, providerAccountId })
        .join('User', 'Account.userId', 'User.id')
        .select('User.*')
        .first();
    },

    // SESSION
    async createSession(data) {
      const [session] = await knex('Session').insert(data).returning('*');
      return session;
    },
    async getSessionAndUser(sessionToken) {
      const session = await knex('Session').where({ sessionToken }).first();
      if (!session) return null;
      const user = await knex('User').where({ id: session.userId }).first();
      return { session, user };
    },
    async updateSession(data) {
      const [session] = await knex('Session')
        .where({ sessionToken: data.sessionToken })
        .update(data)
        .returning('*');
      return session;
    },
    async deleteSession(sessionToken) {
      await knex('Session').where({ sessionToken }).del();
    },

    // VERIFICATION TOKEN
    async createVerificationToken(data) {
      const [token] = await knex('VerificationToken').insert(data).returning('*');
      return token;
    },
    async useVerificationToken({ identifier, token }) {
      const vt = await knex('VerificationToken').where({ identifier, token }).first();
      if (vt) await knex('VerificationToken').where({ identifier, token }).del();
      return vt;
    },
  };
}
