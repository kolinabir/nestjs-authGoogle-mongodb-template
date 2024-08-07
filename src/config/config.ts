export default () => ({
  database: {
    connectionString: process.env.mongoDBUrl,
  },
  jwt: {
    secret: process.env.jwt_secret,
  },
});
