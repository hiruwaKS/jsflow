
// NoSQL Injection Benchmarks (Enriched)

function findUser(req, db) {
  // Vulnerable: Direct pass-through allows { $ne: null } etc.
  const query = req.body.query;
  return db.users.find(query);
}

function findUserWhere(req, db) {
  const username = req.body.username;
  // Vulnerable: JS execution in $where
  // Payload: 'a'; return true; //'
  return db.users.find({ $where: `this.username == '${username}'` });
}

function findUserSafe(req, db) {
  const username = req.body.username;
  if (typeof username !== 'string') return;
  // Safe: Type checking ensures no object injection
  return db.users.find({ username: username });
}

function updateProfile(req, db) {
  const id = req.body.id;
  const data = req.body.data;
  // Vulnerable: data could contain operators like $set, $unset, or even replace the doc
  return db.users.update({ _id: id }, data);
}

module.exports = { 
  findUser,
  findUserWhere,
  findUserSafe,
  updateProfile
};
