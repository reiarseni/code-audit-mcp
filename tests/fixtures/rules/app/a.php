<?php
$users = DB::select("SELECT * FROM users WHERE name = '$name'");    // BAD:laravel-raw-sql-interpolation
$users = DB::select("SELECT * FROM users WHERE id = " . $id);       // BAD:laravel-raw-sql-interpolation
$ok = DB::select('SELECT * FROM users WHERE id = ?', [$id]);
$ok2 = DB::raw('count(*) as total');
$q = User::whereRaw("email = '{$email}'")->get();                   // BAD:laravel-raw-sql-interpolation
$q2 = $query->orderByRaw("FIELD(status, $list)");                   // BAD:laravel-raw-sql-interpolation
$q3 = $query->whereRaw('email = ?', [$email]);
$q4 = $query->selectRaw($expr);
eval($code);                                                        // BAD:php-eval
$k = Redis::keys('user:*');                                         // BAD:redis-keys-command-php
Redis::flushall();                                                  // BAD:redis-flush-in-code-php
$x = env('APP_KEY');                                                // BAD:laravel-env-outside-config
class U extends Model { protected $guarded = []; }                  // BAD:laravel-guarded-empty
$url = "postgres://admin:s3cr3tpw@db:5432/app";                     // BAD:hardcoded-database-url-credentials
$url2 = "postgres://admin:${PASS}@db:5432/app";
$cache = Redis::get('user:1');
