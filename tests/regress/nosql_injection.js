// Mongo-style query built directly from user input (should be flagged).
function findUser(req, db) {
  const query = req.body.query;
  return db.users.find(query);
}

module.exports = { findUser };
