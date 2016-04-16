#!/usr/bin/perl -wl

use HTTP::Tiny;

use feature ':5.10';
no warnings 'experimental::smartmatch';

my ($SERVICE_OK, $FLAG_GET_ERROR, $SERVICE_CORRUPT, $SERVICE_FAIL, $INTERNAL_ERROR) =
  (101, 102, 103, 104, 110);
my %MODES = (check => \&check, get => \&get, put => \&put);
my ($mode, $ip) = splice @ARGV, 0, 2;
my @chars = ('A' .. 'Z', 'a' .. 'z', '_', '0' .. '9');

my $transmitterIp = '10.23.0.14';
#my $transmitterIp = '127.0.0.1';


warn 'Invalid input. Empty mode or ip address.' and exit $INTERNAL_ERROR
  unless defined $mode and defined $ip;
warn 'Invalid mode.' and exit $INTERNAL_ERROR unless $mode ~~ %MODES;
exit $MODES{$mode}->(@ARGV);

sub check {
    return $SERVICE_OK;
}

sub get {
    return $SERVICE_OK;
}


sub put {
  my ($id, $flag) = @_;
  my $data;
  $data .= $chars[rand @chars] for 1 .. 10;

  my $ua = HTTP::Tiny->new(timeout => 10);
  my $response = $ua->get("http://$transmitterIp:10000/addFlag?ip=$ip&id=$id&flag=FLAG$flag");

  return $SERVICE_FAIL if $response->{status} >= 500;
  return $SERVICE_CORRUPT unless $response->{success};
  return $SERVICE_OK;
}
