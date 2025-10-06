#!/usr/bin/env perl
use strict;
use warnings;
use Plack::Request;
use Plack::Response;
use Plack::Builder;
use JSON::MaybeXS;
use DBI;
use Time::Piece;
use Try::Tiny;

# --- Config via ENV (fallbacks provided) ---
my $DSN  = $ENV{RL_PG_DSN}  // 'dbi:Pg:dbname=weblogs;host=127.0.0.1;port=5432';
my $USER = $ENV{RL_PG_USER} // 'weblogs';
my $PASS = $ENV{RL_PG_PASS} // '';
my $UTC  = 1; # API operates in UTC

# Connection pool (one per worker)
my $dbh;
sub dbh {
  return $dbh if $dbh && $dbh->ping;
  $dbh = DBI->connect($DSN, $USER, $PASS, {
    RaiseError => 1,
    AutoCommit => 1,
    pg_server_prepare => 1,
  });
  return $dbh;
}

my $JSON = JSON::MaybeXS->new(utf8 => 1, canonical => 1);

sub parse_range {
  my ($req) = @_;
  my $from = $req->param('from');
  my $to   = $req->param('to');

  if (!$from || !$to) {
    my $to_t   = gmtime();                          # now (UTC)
    my $from_t = gmtime(time() - 24*3600);          # last 24h
    $from = $from_t->datetime . 'Z';
    $to   = $to_t->datetime . 'Z';
  }
  return ($from, $to);
}

sub json {
  my ($code, $data) = @_;
  return [
    $code,
    [ 'Content-Type' => 'application/json; charset=utf-8',
      'Cache-Control' => 'no-store' ],
    [ $JSON->encode($data) ],
  ];
}

sub top_ips {
  my ($req) = @_;
  my ($from, $to) = parse_range($req);
  my $limit = $req->param('limit') // 50;
  $limit = 50 if $limit !~ /^\d+$/ || $limit < 1 || $limit > 500;

  my $sql = q{
    SELECT ip::text AS ip, SUM(cnt)::bigint AS total
    FROM ip_counts
    WHERE bucket_start >= $1 AND bucket_start < $2
    GROUP BY ip
    ORDER BY total DESC
    LIMIT $3
  };
  my $rows = dbh()->selectall_arrayref($sql, { Slice => {} }, $from, $to, $limit);
  return json(200, { from => $from, to => $to, rows => $rows });
}

sub top_uas {
  my ($req) = @_;
  my ($from, $to) = parse_range($req);
  my $limit = $req->param('limit') // 50;
  $limit = 50 if $limit !~ /^\d+$/ || $limit < 1 || $limit > 500;

  my $sql = q{
    SELECT user_agent, SUM(cnt)::bigint AS total
    FROM ua_counts
    WHERE bucket_start >= $1 AND bucket_start < $2
    GROUP BY user_agent
    ORDER BY total DESC
    LIMIT $3
  };
  my $rows = dbh()->selectall_arrayref($sql, { Slice => {} }, $from, $to, $limit);
  return json(200, { from => $from, to => $to, rows => $rows });
}

sub series {
  my ($req) = @_;
  my ($from, $to) = parse_range($req);
  my $q = $req->param('q') // 'ip';
  my $table = $q eq 'ua' ? 'ua_counts' : 'ip_counts';

  my $sql = qq{
    SELECT bucket_start AS ts, SUM(cnt)::bigint AS total
    FROM $table
    WHERE bucket_start >= \$1 AND bucket_start < \$2
    GROUP BY ts
    ORDER BY ts
  };
  my $rows = dbh()->selectall_arrayref($sql, { Slice => {} }, $from, $to);
  return json(200, { from => $from, to => $to, rows => $rows });
}

my $app = sub {
  my $env = shift;
  my $req = Plack::Request->new($env);
  my $path = $req->path_info;
  return json(200, { ok => 1, service => 'redislog-api', endpoints => [qw(/api/top_ips /api/top_uas /api/series)] })
    if $path eq '/' || $path eq '';

  try {
    if ($path eq '/api/top_ips') {
      return top_ips($req);
    } elsif ($path eq '/api/top_uas') {
      return top_uas($req);
    } elsif ($path eq '/api/series') {
      return series($req);
    } else {
      return json(404, { error => 'not_found' });
    }
  } catch {
    my $err = "$_";
    return json(500, { error => 'internal_error', detail => $err });
  };
};

builder {
  enable 'Header', set => [ 'X-Content-Type-Options' => 'nosniff' ];
  enable 'CrossOrigin', origins => '*', headers => [qw(Content-Type)], methods => [qw/GET OPTIONS/];
  $app;
};

