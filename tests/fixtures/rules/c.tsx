export function X({html}: {html: string}) { return <div dangerouslySetInnerHTML={{__html: html}} /> }  // BAD:react-dangerously-set-inner-html
export async function q(pool: any, id: string, redis: any, m: Map<string, string>, prisma: any) {
  await pool.query(`SELECT * FROM t WHERE id = ${id}`)   // BAD:js-sql-template-interpolation
  await pool.query('SELECT * FROM t WHERE id = $1', [id])
  await redis.keys('cache:*')                             // BAD:redis-keys-command-js
  m.keys()
  localStorage.setItem('authToken', id)                   // BAD:token-in-localstorage
  localStorage.setItem('theme', 'dark')
  await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`) // BAD:js-sql-template-interpolation
  await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`
}
