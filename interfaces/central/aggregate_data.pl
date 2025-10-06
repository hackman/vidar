#!/usr/bin/env perl
use strict;
use warnings;
use Redis;
use DBI;
use POSIX qw(strftime floor);

# --- CONFIG ---
my $redis_host = $ENV{RL_REDIS_HOST} // '127.0.0.1';
my $redis_port = $ENV{RL_REDIS_PORT} // 6379;
my $redis_db   = $ENV{RL_REDIS_DB}   // 1;
my $prefix     = $ENV{RL_PREFIX}     // 'rl';
my $bucket_s   = $ENV{RL_BUCKET_S}   // 600;

my $pg_dsn  = $ENV{RL_PG_DSN}  // 'dbi:Pg:dbname=weblogs;host=127.0.0.1;port=5432';
my $pg_user = $ENV{RL_PG_USER} // 'weblogs';
my $pg_pass = $ENV{RL_PG_PASS} // '';

# Determine last full bucket
my $now = time();
my $bucket = $now - ($now % $bucket_s);
$bucket -= $bucket_s; # previous complete bucket

my @gmt = gmtime($bucket);
my $ts_key = sprintf("%04d%02d%02d%02d%02d", $gmt[5]+1900, $gmt[4]+1, $gmt[3], $gmt[2], $gmt[1]);
my $bucket_iso = strftime("%Y-%m-%dT%H:%M:00Z", @gmt);

my $key_ip = "$prefix:ip:$ts_key";
my $key_ua = "$prefix:ua:$ts_key";

# Connect
my $r = Redis->new(server => "$redis_host:$redis_port", reconnect => 3, every => 200_000);
$r->select($redis_db);

my $dbh = DBI->connect($pg_dsn, $pg_user, $pg_pass, { RaiseError => 1, AutoCommit => 1 });

# Prepare UPSERTs
my $sth_ip = $dbh->prepare(q{
  INSERT INTO ip_counts (bucket_start, ip, cnt)
  VALUES ($1::timestamptz, $2::inet, $3::bigint)
  ON CONFLICT (bucket_start, ip) DO UPDATE SET cnt = ip_counts.cnt + EXCLUDED.cnt
});
my $sth_ua = $dbh->prepare(q{
  INSERT INTO ua_counts (bucket_start, user_agent, cnt)
  VALUES ($1::timestamptz, $2::text, $3::bigint)
  ON CONFLICT (bucket_start, user_agent) DO UPDATE SET cnt = ua_counts.cnt + EXCLUDED.cnt
});

# Fetch and store IPs
my %ips = $r->hgetall($key_ip);
for my $ip (keys %ips) {
  my $cnt = $ips{$ip} // 0;
  next unless $cnt =~ /^\d+$/;
  $sth_ip->execute($bucket_iso, $ip, $cnt);
}

# Fetch and store UAs
my %uas = $r->hgetall($key_ua);
for my $ua (keys %uas) {
  my $cnt = $uas{$ua} // 0;
  next unless $cnt =~ /^\d+$/;
  $sth_ua->execute($bucket_iso, $ua, $cnt);
}

# Optional: cleanup processed keys
$r->del($key_ip) if %ips;
$r->del($key_ua) if %uas;

print "Aggregated bucket $bucket_iso (keys: $key_ip, $key_ua)\n";

