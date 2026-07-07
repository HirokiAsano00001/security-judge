// VULNERABILITY FIXTURE - mass assignment via Object.assign(req.body)
export function updateUser(req, res, users) {
  const user = users.find((u) => u.id === Number(req.params.id))
  // Unrestricted merge of user-controlled body — role/isAdmin can be injected.
  Object.assign(user, req.body)
  res.json(user)
}
