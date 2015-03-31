#!/usr/bin/perl
use 5.10.0;
use utf8;
use strict;
use warnings;
use open qw( :std :utf8 );
use autodie qw( open close );
use Data::Dumper;
use Path::Class qw( file );
use List::MoreUtils qw( first_index );

$Data::Dumper::Terse    = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

my @lines = Path::Class::file( "lib/Linux/Proc/Net/Snmp.pm" )->slurp( chomp => 1 );
my $index = first_index { $_ eq "__END__" } @lines;
$#lines = $index - 1
    if $index;

my $header = <<'END_HEADER';
#!/usr/bin/perl -s
use utf8;
use strict;
use warnings;
use Data::Dumper;

our $interval ||= 2;
our $verbose;

$Data::Dumper::Terse    = 1;
$Data::Dumper::Sortkeys = 1;
$Data::Dumper::Indent   = 1;

END_HEADER

my $body = <<'END_BODY';
package main;
my $reader = Linux::Proc::Net::Snmp->get_alias;

my @field_specs = qw(

);

$|++;

while ( 1 ) {
    my $measured_at = time;
    my( $stats_ref, $index_ref ) = $reader->parse_lines( $reader->read_file( ) );

    if ( $verbose ) {
        my %stat = $reader->construct_stat( $stats_ref, $index_ref );
        print $measured_at, "\t", Data::Dumper->new( [ \%stat ] )->Indent( 0 )->Dump, "\n";
    }
    else {
        my @fields = $reader->extract_fields( \@field_specs, $stats_ref, $index_ref );
        print $measured_at, "\t", join( "\t", @fields ), "\n";
    }

    sleep $interval;
}

exit;

END_BODY

print $header, ( map { $_, "\n" } @lines ), $body;

exit;
