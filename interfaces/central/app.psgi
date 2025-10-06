#!/usr/bin/perl
# Run with taint mode:
# PERL5OPT='-T' plackup -s Starman -l 127.0.0.1:5001 app.psgi
use strict;
use warnings;
use Plack::Builder;
use Plack::Request;
use JSON::MaybeXS;
use Config::Tiny;
use DBI;
use Time::Piece;
use Try::Tiny;

$ENV{PATH} = '/usr/bin:/bin';
delete @ENV{qw(IFS CDPATH ENV BASH_ENV)};

sub _untaint_abs_path {
	my ($s) = @_;
	return undef unless defined $s;
	if ($s =~ m{\A(/[\w\.\-\+/]+)\z}) { return $1 }
	return undef;
}

sub _untaint_iso8601 {
	my ($s) = @_;
	return undef unless defined $s;
	if ($s =~ /\A(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)\z/) { return $1 }
	return undef;
}

sub _untaint_digit {
	my ($s, $min, $max, $default) = @_;
	return $default unless defined $s;
	if ($s =~ /\A(\d+)\z/) {
		my $n = $1 + 0;
		$n = $min if defined $min && $n < $min;
		$n = $max if defined $max && $n > $max;
		return $n;
	}
	return $default;
}

sub _untaint_server_name {
	my ($s) = @_;
	return undef unless defined $s;
	if ($s =~ /\A([A-Za-z0-9._-]{1,128})\z/) { return $1 }
	return undef;
}

sub _now_utc_iso  { gmtime->datetime . 'Z' }
sub _24h_ago_iso  { (gmtime(time - 24*3600))->datetime . 'Z' }

my $ini_from_env = $ENV{CENTRAL_API_INI};
my $ini_path = _untaint_abs_path($ini_from_env) // 'central-api.ini';
if ($ini_path !~ m{^/}) {
	if ($ini_path =~ /\A([\w.\-]+)\z/) { $ini_path = $1 }
	else { die "Refusing tainted ini path\n" }
}

my $config = Config::Tiny->read($ini_path)
	or die "Failed to read config $ini_path: " . Config::Tiny->error();

my $allow_origin = $config->{api}->{allow_origin} // '*';

my ($dbh, %query);

sub _dbh {
	return $dbh if $dbh && $dbh->ping;
	$dbh = DBI->connect($config->{pg}->{dsn}, $config->{pg}->{user}, $config->{pg}->{pass}, {
		RaiseError => 1,
		AutoCommit => 1,
		pg_server_prepare => 1,
	});
	_prepare_statements($dbh);
	return $dbh;
}

sub _prepare_statements {
	my ($d) = @_;
	$query{servers} = $d->prepare_cached(q{
		SELECT server_name FROM servers ORDER BY server_name
	});
	$query{top_ips_total} = $d->prepare_cached(q{
		SELECT ip::text AS ip, SUM(cnt)::bigint AS total
		FROM ip_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY ip ORDER BY total DESC LIMIT $3
	});
	$query{top_ips_server} = $d->prepare_cached(q{
		SELECT ip::text AS ip, SUM(cnt)::bigint AS total
		FROM ip_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2 AND server_name = $3
		GROUP BY ip ORDER BY total DESC LIMIT $4
	});
	$query{top_uas_total} = $d->prepare_cached(q{
		SELECT user_agent, SUM(cnt)::bigint AS total
		FROM ua_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY user_agent ORDER BY total DESC LIMIT $3
	});
	$query{top_uas_server} = $d->prepare_cached(q{
		SELECT user_agent, SUM(cnt)::bigint AS total
		FROM ua_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2 AND server_name = $3
		GROUP BY user_agent ORDER BY total DESC LIMIT $4
	});
	$query{series_ip_total} = $d->prepare_cached(q{
		SELECT bucket_start AS ts, SUM(cnt)::bigint AS total
		FROM ip_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY ts ORDER BY ts
	});
	$query{series_ip_server} = $d->prepare_cached(q{
		SELECT server_name, bucket_start AS ts, SUM(cnt)::bigint AS total
		FROM ip_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY server_name, ts ORDER BY server_name, ts
	});
	$query{series_ua_total} = $d->prepare_cached(q{
		SELECT bucket_start AS ts, SUM(cnt)::bigint AS total
		FROM ua_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY ts ORDER BY ts
	});
	$query{series_ua_server} = $d->prepare_cached(q{
		SELECT server_name, bucket_start AS ts, SUM(cnt)::bigint AS total
		FROM ua_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2
		GROUP BY server_name, ts ORDER BY server_name, ts
	});
	$query{ip_breakdown} = $d->prepare_cached(q{
		SELECT server_name, SUM(cnt)::bigint AS total
		FROM ip_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2 AND ip = $3::inet
		GROUP BY server_name ORDER BY total DESC
	});
	$query{ua_breakdown} = $d->prepare_cached(q{
		SELECT server_name, SUM(cnt)::bigint AS total
		FROM ua_counts_agg
		WHERE bucket_start >= $1 AND bucket_start < $2 AND user_agent = $3
		GROUP BY server_name ORDER BY total DESC
	});
}

my $json = JSON::MaybeXS->new(utf8 => 1, canonical => 1);
sub _json {
	my ($code, $data) = @_;
	[
		$code,
		[
			'Content-Type'  => 'application/json; charset=utf-8',
			'Cache-Control' => 'no-store'
		],
		[ $json->encode($data) ]
	];
}

sub _parse_range {
	my ($req) = @_;
	my $from = _untaint_iso8601($req->param('from')) // _24h_ago_iso();
	my $to   = _untaint_iso8601($req->param('to'))   // _now_utc_iso();
	return ($from, $to);
}

sub ep_servers {
	my $dbh = _dbh();
	$query{servers}->execute();
	my $rows = $query{servers}->fetchall_arrayref({});
	return _json 200, { rows => $rows };
}

sub ep_top_ips {
	my ($req) = @_;
	my ($from, $to) = _parse_range($req);
	my $limit  = _untaint_digit($req->param('limit'), 1, 500, 50);
	my $server = $req->param('server');
	my $dbh = _dbh();
	if (defined $server && lc($server) ne 'all') {
		my $srv = _untaint_server_name($server) // return _json 400, { error => 'invalid server' };
		$query{top_ips_server}->execute($from, $to, $srv, $limit);
		my $rows = $query{top_ips_server}->fetchall_arrayref({});
		return _json 200, { from=>$from, to=>$to, rows=>$rows };
	} else {
		$query{top_ips_total}->execute($from, $to, $limit);
		my $rows = $query{top_ips_total}->fetchall_arrayref({});
		return _json 200, { from=>$from, to=>$to, rows=>$rows };
	}
}

sub ep_top_uas {
	my ($req) = @_;
	my ($from, $to) = _parse_range($req);
	my $limit  = _untaint_digit($req->param('limit'), 1, 500, 50);
	my $server = $req->param('server');
	my $dbh = _dbh();
	if (defined $server && lc($server) ne 'all') {
		my $srv = _untaint_server_name($server) // return _json 400, { error => 'invalid server' };
		$query{top_uas_server}->execute($from, $to, $srv, $limit);
		my $rows = $query{top_uas_server}->fetchall_arrayref({});
		return _json 200, { from=>$from, to=>$to, rows=>$rows };
	} else {
		$query{top_uas_total}->execute($from, $to, $limit);
		my $rows = $query{top_uas_total}->fetchall_arrayref({});
		return _json 200, { from=>$from, to=>$to, rows=>$rows };
	}
}

sub ep_series {
	my ($req) = @_;
	my ($from, $to) = _parse_range($req);
	my $q     = $req->param('q')     // 'ip';
	my $group = $req->param('group') // 'total';
	$q     = ($q eq 'ua') ? 'ua' : 'ip';
	$group = ($group eq 'server') ? 'server' : 'total';
	my $dbh = _dbh();
	my $key = "series_${q}_$group";
	$query{$key}->execute($from, $to);
	my $rows = $query{$key}->fetchall_arrayref({});
	return _json 200, { from=>$from, to=>$to, rows=>$rows };
}

sub ep_ip_breakdown {
	my ($req) = @_;
	my ($from, $to) = _parse_range($req);
	my $ip = $req->param('ip') // return _json 400, { error => 'missing ip' };
	if ($ip !~ /\A([0-9A-Fa-f:.]{1,60})\z/) { return _json 400, { error => 'invalid ip' } }
	$ip = $1;
	my $dbh = _dbh();
	$query{ip_breakdown}->execute($from, $to, $ip);
	my $rows = $query{ip_breakdown}->fetchall_arrayref({});
	return _json 200, { ip=>$ip, from=>$from, to=>$to, rows=>$rows };
}

sub ep_ua_breakdown {
	my ($req) = @_;
	my ($from, $to) = _parse_range($req);
	my $ua = $req->param('ua') // return _json 400, { error => 'missing ua' };
	if ($ua !~ /\A([\x20-\x7E]{1,512})\z/) { return _json 400, { error => 'invalid ua' } }
	$ua = $1;
	my $dbh = _dbh();
	$query{ua_breakdown}->execute($from, $to, $ua);
	my $rows = $query{ua_breakdown}->fetchall_arrayref({});
	return _json 200, { user_agent=>$ua, from=>$from, to=>$to, rows=>$rows };
}

my $app = sub {
	my $env = shift;
	my $req = Plack::Request->new($env);
	my $p   = $req->path_info // '/';
	return _json 200, {
		ok => 1, service => 'central-redislog',
		endpoints => [qw(
			/api/servers
			/api/top_ips
			/api/top_uas
			/api/series
			/api/ip_breakdown
			/api/ua_breakdown
		)]
	} if $p eq '/' || $p eq '';
	return try {
		return ep_servers()           if $p eq '/api/servers';
		return ep_top_ips($req)       if $p eq '/api/top_ips';
		return ep_top_uas($req)       if $p eq '/api/top_uas';
		return ep_series($req)        if $p eq '/api/series';
		return ep_ip_breakdown($req)  if $p eq '/api/ip_breakdown';
		return ep_ua_breakdown($req)  if $p eq '/api/ua_breakdown';
		_json 404, { error => 'not_found' }
	} catch {
		_json 500, { error => 'internal_error', detail => "$_" }
	};
};

builder {
	enable 'Header', set => [
		'X-Content-Type-Options' => 'nosniff',
		'Referrer-Policy'        => 'no-referrer-when-downgrade',
	];
	enable 'CrossOrigin',
		origins => $allow_origin,
		headers => [qw(Content-Type)],
		methods => [qw/GET OPTIONS/];
	$app;
};

