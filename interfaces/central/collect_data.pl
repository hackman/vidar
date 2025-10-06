#!/usr/bin/env perl
use strict;
use warnings;
use Config::Tiny;
use DBI;
use Time::Piece;
use Time::Seconds;
use Try::Tiny;

# -------- Load config (INI) --------
my $config_file = $ARGV[0] // 'collector.ini';
die "Config file not found: $config_file\n" unless -f $config_file;
my $cfg = Config::Tiny->read($config_file)
  or die "Failed to read config: " . Config::Tiny->error();

my $CENTRAL_DSN  = $cfg->{central}->{dsn}  // die "Missing central.dsn";
my $CENTRAL_USER = $cfg->{central}->{user} // die "Missing central.user";
my $CENTRAL_PASS = $cfg->{central}->{pass} // '';

my $BATCH_LIMIT    = $cfg->{options}->{batch_limit}    // 50000;
my $LOOKBACK_HOURS = $cfg->{options}->{lookback_hours} // 720;

# -------- DB helpers --------
sub dbh {
    my ($dsn, $user, $pass) = @_;
    return DBI->connect($dsn, $user, $pass, {
        RaiseError => 1,
        AutoCommit => 1,
        pg_server_prepare => 1,
    });
}

my $central = dbh($CENTRAL_DSN, $CENTRAL_USER, $CENTRAL_PASS);

# Prepare common statements
my $ins_server = $central->prepare(q{
  INSERT INTO servers(server_name) VALUES ($1)
  ON CONFLICT (server_name) DO NOTHING
});

my $sel_sync = $central->prepare(q{
  SELECT last_bucket FROM sync_state WHERE server_name=$1 AND table_name=$2
});

my $upsert_sync = $central->prepare(q{
  INSERT INTO sync_state(server_name, table_name, last_bucket)
  VALUES ($1,$2,$3)
  ON CONFLICT (server_name, table_name)
  DO UPDATE SET last_bucket = EXCLUDED.last_bucket
});

my $ins_ip = $central->prepare(q{
  INSERT INTO ip_counts_agg (bucket_start, server_name, ip, cnt)
  VALUES ($1,$2,$3,$4)
  ON CONFLICT (bucket_start, server_name, ip)
  DO UPDATE SET cnt = ip_counts_agg.cnt + EXCLUDED.cnt
});

my $ins_ua = $central->prepare(q{
  INSERT INTO ua_counts_agg (bucket_start, server_name, user_agent, cnt)
  VALUES ($1,$2,$3,$4)
  ON CONFLICT (bucket_start, server_name, user_agent)
  DO UPDATE SET cnt = ua_counts_agg.cnt + EXCLUDED.cnt
});

sub process_table_for_node {
    my (%args) = @_;
    my $node_name  = $args{node_name};
    my $local_dbh  = $args{local_dbh};
    my $table_name = $args{table_name};

    # 1) find last checkpoint
    $sel_sync->execute($node_name, $table_name);
    my ($last_bucket) = $sel_sync->fetchrow_array;
    my $from_bucket;
    if ($last_bucket) {
        $from_bucket = $last_bucket;
    } else {
        my $fallback = gmtime() - ($LOOKBACK_HOURS * ONE_HOUR);
        $from_bucket = $fallback->datetime . 'Z';
    }

    # 2) fetch new rows
    my $sql = ($table_name eq 'ip_counts')
      ? q{SELECT bucket_start, ip::text AS k, cnt FROM ip_counts WHERE bucket_start > $1 ORDER BY bucket_start LIMIT $2}
      : q{SELECT bucket_start, user_agent AS k, cnt FROM ua_counts WHERE bucket_start > $1 ORDER BY bucket_start LIMIT $2};

    my $sth = $local_dbh->prepare($sql);
    $sth->execute($from_bucket, $BATCH_LIMIT);

    my ($rows, $max_bucket_seen) = (0, undef);
    while (my $r = $sth->fetchrow_hashref) {
        my ($bucket_start, $key, $cnt) = @{$r}{qw/bucket_start k cnt/};
        next unless defined $key && defined $cnt;
        if ($table_name eq 'ip_counts') {
            $ins_ip->execute($bucket_start, $node_name, $key, $cnt);
        } else {
            $ins_ua->execute($bucket_start, $node_name, $key, $cnt);
        }
        $rows++;
        $max_bucket_seen = $bucket_start if !defined $max_bucket_seen || $bucket_start gt $max_bucket_seen;
    }

    if ($rows && $max_bucket_seen) {
        $upsert_sync->execute($node_name, $table_name, $max_bucket_seen);
    }

    return $rows;
}

# -------- Main loop --------
for my $section (keys %$cfg) {
    next unless $section =~ /^node\s+"?([^"]+)"?$/;
    my $name = $1;
    print "[*] Node: $name\n";

    my $dsn  = $cfg->{$section}->{dsn}  or warn "  missing DSN\n" and next;
    my $user = $cfg->{$section}->{user} // '';
    my $pass = $cfg->{$section}->{pass} // '';

    $ins_server->execute($name);

    my $local;
    try {
        $local = dbh($dsn, $user, $pass);
    } catch {
        warn "  ! cannot connect to $name local DB: $_";
        next;
    };

    for my $tbl (qw/ip_counts ua_counts/) {
        my $count = 0;
        try {
            $count = process_table_for_node(
                node_name  => $name,
                local_dbh  => $local,
                table_name => $tbl,
            );
            printf "  [+] %-10s: %d rows merged\n", $tbl, $count;
        } catch {
            warn "  ! error merging $tbl for $name: $_";
        };
    }
}
print "[OK] Done.\n";

