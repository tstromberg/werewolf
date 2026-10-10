// overleaf-admin: makes the overleaf form's administrator, before Overleaf
// serves anything, so no first visitor claims the machine at /launchpad.
// overleaf-start runs it after the migrations: the email is the config's
// admin-email setting (OVERLEAF_ADMIN_EMAIL), the password its
// admin-password file, which leash copied to /tmp. With an administrator
// already there it changes nothing: a password changed in Overleaf stays.
import fs from 'node:fs'
import { db, waitForDb } from '/overleaf/services/web/app/src/infrastructure/mongodb.mjs'
import UserRegistrationHandler from '/overleaf/services/web/app/src/Features/User/UserRegistrationHandler.mjs'

function say(event, fields = {}) {
  console.log(`overleaf-admin: ${JSON.stringify({ event, ...fields })}`)
}

try {
  await waitForDb()
  const email = process.env.OVERLEAF_ADMIN_EMAIL
  if (await db.users.findOne({ isAdmin: true }, { projection: { _id: 1 } })) {
    say('kept')
  } else {
    const password = fs.readFileSync('/tmp/admin-password', 'utf8').replace(/\r?\n$/, '')
    const user = await UserRegistrationHandler.promises.registerNewUser({ email, password })
    await db.users.updateOne({ _id: user._id }, { $set: { isAdmin: true } })
    say('made', { email })
  }
  process.exit(0)
} catch (err) {
  say('failed', { why: err.message })
  process.exit(1)
}
